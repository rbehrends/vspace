#include "vspace.h"
#include <cstdlib>
#include <set>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>



namespace vspace {

static AllocationFailureHandler allocation_failure_handler = NULL;

void set_allocation_failure_handler(AllocationFailureHandler handler) {
  allocation_failure_handler = handler;
}

static void allocation_failure(size_t size) {
  if (allocation_failure_handler != NULL)
    allocation_failure_handler(size);
  else
    std::fprintf(stderr, "vspace: unable to allocate %lu bytes\n",
        (unsigned long) size);
  std::abort();
}

namespace internals {

VMem VMem::vmem_global;

static const uint32_t FILE_MAGIC = UINT32_C(0x56535043);
static const uint32_t FILE_VERSION = 2;
#if __cplusplus >= 201103L
static const uint32_t LAYOUT_ID = UINT32_C(0x432b3131);
#else
static const uint32_t LAYOUT_ID = UINT32_C(0x432b3938);
#endif

void pthread_fatal(const char *operation, int error) {
  std::fprintf(stderr, "vspace: %s failed: %s\n", operation,
      std::strerror(error));
  std::abort();
}

SharedMutex::SharedMutex(bool recursive) {
  pthread_mutexattr_t attr;
  int error = pthread_mutexattr_init(&attr);
  if (error != 0)
    pthread_fatal("pthread_mutexattr_init", error);
  error = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  if (error == 0 && recursive)
    error = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  if (error == 0)
    error = pthread_mutex_init(&_mutex, &attr);
  int destroy_error = pthread_mutexattr_destroy(&attr);
  if (error != 0)
    pthread_fatal("pthread_mutex_init", error);
  if (destroy_error != 0)
    pthread_fatal("pthread_mutexattr_destroy", destroy_error);
}

SharedMutex::~SharedMutex() {
  int error = pthread_mutex_destroy(&_mutex);
  if (error != 0)
    pthread_fatal("pthread_mutex_destroy", error);
}

void SharedMutex::lock() {
  int error = pthread_mutex_lock(&_mutex);
  if (error != 0)
    pthread_fatal("pthread_mutex_lock", error);
}

void SharedMutex::unlock() {
  int error = pthread_mutex_unlock(&_mutex);
  if (error != 0)
    pthread_fatal("pthread_mutex_unlock", error);
}

SharedCondition::SharedCondition() {
  pthread_condattr_t attr;
  int error = pthread_condattr_init(&attr);
  if (error != 0)
    pthread_fatal("pthread_condattr_init", error);
  error = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  if (error == 0)
    error = pthread_cond_init(&_condition, &attr);
  int destroy_error = pthread_condattr_destroy(&attr);
  if (error != 0)
    pthread_fatal("pthread_cond_init", error);
  if (destroy_error != 0)
    pthread_fatal("pthread_condattr_destroy", destroy_error);
}

SharedCondition::~SharedCondition() {
  int error = pthread_cond_destroy(&_condition);
  if (error != 0)
    pthread_fatal("pthread_cond_destroy", error);
}

void SharedCondition::wait(SharedMutex &mutex) {
  int error = pthread_cond_wait(&_condition, mutex.native_handle());
  if (error != 0)
    pthread_fatal("pthread_cond_wait", error);
}

void SharedCondition::signal() {
  int error = pthread_cond_signal(&_condition);
  if (error != 0)
    pthread_fatal("pthread_cond_signal", error);
}

void SharedCondition::broadcast() {
  int error = pthread_cond_broadcast(&_condition);
  if (error != 0)
    pthread_fatal("pthread_cond_broadcast", error);
}

static void release_process_slot() {
  if (vmem.metapage == NULL || vmem.current_process < 0)
    return;
  vmem.metapage->process_table_mutex.lock();
  ProcessInfo &info = vmem.metapage->process_info[vmem.current_process];
  if (info.pid == getpid()) {
    info.wait_context.notify_mutex.lock();
    if (info.wait_context.state != WaitIdle)
      pthread_fatal("release process with active wait", EBUSY);
    info.pid = 0;
    info.slot_state = ProcessUnused;
    info.wait_context.notify_mutex.unlock();
  }
  vmem.metapage->process_table_mutex.unlock();
  vmem.current_process = -1;
}

static bool register_process() {
  vmem.metapage->process_table_mutex.lock();
  for (int p = 0; p < MAX_PROCESS; p++) {
    ProcessInfo &info = vmem.metapage->process_info[p];
    if (info.slot_state == ProcessUnused) {
      info.wait_context.notify_mutex.lock();
      info.slot_state = ProcessStarting;
      info.process_incarnation++;
      info.pid = getpid();
      info.slot_state = ProcessRunning;
      info.wait_context.notify_mutex.unlock();
      vmem.current_process = p;
      vmem.metapage->process_table_mutex.unlock();
      std::atexit(release_process_slot);
      return true;
    }
  }
  vmem.metapage->process_table_mutex.unlock();
  return false;
}

size_t VMem::filesize() {
  struct stat stat;
  return fstat(fd, &stat) == 0 ? (size_t) stat.st_size : 0;
}

Status VMem::init(int fd) {
  this->fd = fd;
  file_handle = NULL;
  current_process = -1;
  metapage = NULL;
  freelist = NULL;
  for (int i = 0; i < MAX_SEGMENTS; i++)
    segments[i] = VSeg(NULL);
  if (!lock_metapage())
    return Status(ErrOS);
  struct stat stat;
  if (fstat(fd, &stat) < 0) {
    unlock_metapage();
    return Status(ErrOS);
  }
  Status result = init_metapage(stat.st_size == 0);
  unlock_metapage();
  if (!result)
    return result;
  freelist = metapage->freelist;
  if (!register_process()) {
    munmap(metapage, METABLOCK_SIZE);
    metapage = NULL;
    freelist = NULL;
    return Status(ErrGeneral);
  }
  return Status(ErrNone);
}

Status VMem::init() {
  FILE *fp = tmpfile();
  if (fp == NULL)
    return Status(ErrFile);
  Status result = init(fileno(fp));
  if (!result.ok()) {
    fclose(fp);
    return result;
  }
  file_handle = fp;
  return Status(ErrNone);
}

Status VMem::init(const char *path) {
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return Status(ErrFile);
  Status result = init(fd);
  if (!result) {
    close(fd);
    return result;
  }
  return Status(ErrNone);
}

void VMem::deinit() {
  release_process_slot();
  for (int i = 0; i < MAX_SEGMENTS; i++) {
    if (!segments[i].is_free())
      munmap(segments[i].base, SEGMENT_SIZE);
    segments[i] = VSeg(NULL);
  }
  munmap(metapage, METABLOCK_SIZE);
  metapage = NULL;
  freelist = NULL;
  if (file_handle) {
    fclose(file_handle);
    file_handle = NULL;
  } else {
    close(fd);
  }
}

void *VMem::mmap_segment(int seg) {
  void *map = mmap(NULL, SEGMENT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
      METABLOCK_SIZE + seg * SEGMENT_SIZE);
  if (map == MAP_FAILED) {
    perror("mmap");
    abort();
  }
  return map;
}

void VMem::add_segment() {
  int seg = metapage->segment_count++;
  if (ftruncate(fd,
      METABLOCK_SIZE + metapage->segment_count * SEGMENT_SIZE) < 0) {
    perror("ftruncate");
    abort();
  }
  void *map_addr = mmap_segment(seg);
  segments[seg] = VSeg(map_addr);
  Block *top = block_ptr(seg * SEGMENT_SIZE);
  top->next = freelist[LOG2_SEGMENT_SIZE];
  top->prev = VADDR_NULL;
  top->mark_as_free(LOG2_SEGMENT_SIZE);
  freelist[LOG2_SEGMENT_SIZE] = seg * SEGMENT_SIZE;
}

static void lock_allocator() {
  vmem.metapage->allocator_lock.lock();
}

static void unlock_allocator() {
  vmem.metapage->allocator_lock.unlock();
}

char *validate_allocator() {
  static char error[256];
  std::set<vaddr_t> listed_free;
  std::set<vaddr_t> physical_free;
  struct AllocatorLockGuard {
    AllocatorLockGuard() { lock_allocator(); }
    ~AllocatorLockGuard() { unlock_allocator(); }
  } lock_guard;

  for (int level = 0; level <= LOG2_SEGMENT_SIZE; level++) {
    vaddr_t previous = VADDR_NULL;
    for (vaddr_t current = vmem.freelist[level]; current != VADDR_NULL;) {
      size_t segno = vmem.segment_no(current);
      segaddr_t addr = vmem.segaddr(current);
      if (segno >= (size_t) vmem.metapage->segment_count) {
        std::snprintf(error, sizeof(error),
                    "free-list level %d contains block %lu in nonexistent segment %lu",
                    level, (unsigned long) current, (unsigned long) segno);
        return error;
      }
      if ((addr & ((size_t(1) << level) - 1)) != 0) {
        std::snprintf(error, sizeof(error),
                    "free-list block %lu is not aligned for level %d",
            (unsigned long) current, level);
        return error;
      }
      if (!listed_free.insert(current).second) {
        std::snprintf(error, sizeof(error),
                    "free-list block %lu occurs more than once",
            (unsigned long) current);
        return error;
      }
      vmem.ensure_is_mapped(current);
      Block *block = vmem.block_ptr(current);
      if (!block->is_free()) {
        std::snprintf(error, sizeof(error),
                    "free-list level %d contains allocated block %lu",
            level, (unsigned long) current);
        return error;
      }
      if (block->level() != level) {
        std::snprintf(error, sizeof(error),
                    "free-list block %lu records level %d instead of %d",
            (unsigned long) current, block->level(), level);
        return error;
      }
      if (block->prev != previous) {
        std::snprintf(error, sizeof(error),
                    "free-list block %lu has previous link %lu instead of %lu",
            (unsigned long) current, (unsigned long) block->prev,
            (unsigned long) previous);
        return error;
      }
      previous = current;
      current = block->next;
    }
  }

  const int minimum_level = find_level(sizeof(Block));
  for (int seg = 0; seg < vmem.metapage->segment_count; seg++) {
    vaddr_t segment_start = vmem.vaddr(seg, 0);
    vmem.ensure_is_mapped(segment_start);
    for (segaddr_t addr = 0; addr < SEGMENT_SIZE;) {
      Block *block = vmem.segments[seg].block_ptr(addr);
      int level = block->level();
      if (level < minimum_level || level > LOG2_SEGMENT_SIZE) {
        std::snprintf(error, sizeof(error),
                    "block %lu records invalid level %d",
            (unsigned long) vmem.vaddr(seg, addr), level);
        return error;
      }
      if ((addr & ((size_t(1) << level) - 1)) != 0) {
        std::snprintf(error, sizeof(error),
                    "block %lu is not aligned for level %d",
            (unsigned long) vmem.vaddr(seg, addr), level);
        return error;
      }
      if ((size_t(1) << level) > SEGMENT_SIZE - addr) {
        std::snprintf(error, sizeof(error),
                    "block %lu at level %d extends beyond its segment",
            (unsigned long) vmem.vaddr(seg, addr), level);
        return error;
      }
      if (block->is_free())
        physical_free.insert(vmem.vaddr(seg, addr));
      addr += size_t(1) << level;
    }
  }

  if (listed_free != physical_free) {
    std::snprintf(error, sizeof(error),
            "physical free blocks do not match free lists (%lu physical, %lu listed)",
        (unsigned long) physical_free.size(), (unsigned long) listed_free.size());
    return error;
  }

  for (std::set<vaddr_t>::const_iterator i = physical_free.begin();
      i != physical_free.end(); ++i) {
    Block *block = vmem.block_ptr(*i);
    int level = block->level();
    if (level < LOG2_SEGMENT_SIZE) {
      vaddr_t buddy = vmem.vaddr(vmem.segment_no(*i),
          find_buddy(vmem.segaddr(*i), level));
      if (physical_free.find(buddy) != physical_free.end()
          && vmem.block_ptr(buddy)->level() == level) {
        std::snprintf(error, sizeof(error),
                    "free buddy blocks %lu and %lu at level %d were not coalesced",
            (unsigned long) *i, (unsigned long) buddy, level);
        return error;
      }
    }
  }

  return NULL;
}

static void print_freelists() {
  for (int i = 0; i <= LOG2_SEGMENT_SIZE; i++) {
    vaddr_t vaddr = vmem.freelist[i];
    if (vaddr != VADDR_NULL) {
      std::printf("%2d: %ld", i, vaddr);
      vaddr_t prev = block_ptr(vaddr)->prev;
      if (prev != VADDR_NULL) {
        std::printf("(%ld)", prev);
      }
      assert(block_ptr(vaddr)->prev == VADDR_NULL);
      for (;;) {
        vaddr_t last_vaddr = vaddr;
        Block *block = block_ptr(vaddr);
        vaddr = block->next;
        if (vaddr == VADDR_NULL)
          break;
        std::printf(" -> %ld", vaddr);
        vaddr_t prev = block_ptr(vaddr)->prev;
        if (prev != last_vaddr) {
          std::printf("(%ld)", prev);
        }
      }
      std::printf("\n");
    }
  }
  std::fflush(stdout);
}

void vmem_free(vaddr_t vaddr) {
  lock_allocator();
  vaddr -= offsetof(Block, data);
  vmem.ensure_is_mapped(vaddr);
  size_t segno = vmem.segment_no(vaddr);
  VSeg seg = vmem.segment(vaddr);
  segaddr_t addr = vmem.segaddr(vaddr);
  int level = seg.block_ptr(addr)->level();
  assert(!seg.is_free(addr));
  while (level < LOG2_SEGMENT_SIZE) {
    segaddr_t buddy = find_buddy(addr, level);
    Block *block = seg.block_ptr(buddy);
    // is buddy free and at the same level?
    if (!block->is_free() || block->level() != level)
      break;
    // remove buddy from freelist.
    Block *prev = vmem.block_ptr(block->prev);
    Block *next = vmem.block_ptr(block->next);
    block->data[0] = level;
    if (prev) {
      assert(prev->next == vmem.vaddr(segno, buddy));
      prev->next = block->next;
    } else {
      // head of freelist.
      assert(vmem.freelist[level] == vmem.vaddr(segno, buddy));
      vmem.freelist[level] = block->next;
    }
    if (next) {
      assert(next->prev == vmem.vaddr(segno, buddy));
      next->prev = block->prev;
    }
    // coalesce block with buddy
    level++;
    if (buddy < addr)
      addr = buddy;
  }
  // Add coalesced block to free list
  Block *block = seg.block_ptr(addr);
  block->prev = VADDR_NULL;
  block->next = vmem.freelist[level];
  block->mark_as_free(level);
  vaddr_t blockaddr = vmem.vaddr(segno, addr);
  if (block->next != VADDR_NULL)
    vmem.block_ptr(block->next)->prev = blockaddr;
  vmem.freelist[level] = blockaddr;
  unlock_allocator();
}

vaddr_t vmem_alloc(size_t size) {
  const size_t overhead = offsetof(Block, data);
  if (size > SEGMENT_SIZE - overhead)
    allocation_failure(size);

  size_t alloc_size = size + overhead;
  int level = find_level(alloc_size);
  lock_allocator();
  int flevel = level;
  while (flevel < LOG2_SEGMENT_SIZE && vmem.freelist[flevel] == VADDR_NULL)
    flevel++;
  if (vmem.freelist[flevel] == VADDR_NULL) {
    if (vmem.metapage->segment_count >= (int) MAX_SEGMENTS) {
      unlock_allocator();
      allocation_failure(size);
    }
    vmem.add_segment();
  }
  vmem.ensure_is_mapped(vmem.freelist[flevel]);
  while (flevel > level) {
    // get and split a block
    vaddr_t blockaddr = vmem.freelist[flevel];
    assert((blockaddr & ((size_t(1) << flevel) - 1)) == 0);
    Block *block = vmem.block_ptr(blockaddr);
    vmem.freelist[flevel] = block->next;
    if (vmem.freelist[flevel] != VADDR_NULL)
      vmem.block_ptr(vmem.freelist[flevel])->prev = VADDR_NULL;
    vaddr_t blockaddr2 = blockaddr + (size_t(1) << (flevel - 1));
    Block *block2 = vmem.block_ptr(blockaddr2);
    flevel--;
    block2->next = vmem.freelist[flevel];
    block2->prev = blockaddr;
    block->next = blockaddr2;
    block->prev = VADDR_NULL;
    block->mark_as_free(flevel);
    block2->mark_as_free(flevel);
    vmem.freelist[flevel] = blockaddr;
  }
  assert(vmem.freelist[level] != VADDR_NULL);
  Block *block = vmem.block_ptr(vmem.freelist[level]);
  vaddr_t vaddr = vmem.freelist[level];
  vaddr_t result = vaddr + offsetof(Block, data);
  vmem.freelist[level] = block->next;
  if (block->next != VADDR_NULL)
    vmem.block_ptr(block->next)->prev = VADDR_NULL;
  block->mark_as_allocated(vaddr, level);
  unlock_allocator();
  memset(block->data, 0, size);
  return result;
}

static int set_file_lock(size_t offset, short type) {
  struct flock lock_info;
  std::memset(&lock_info, 0, sizeof(lock_info));
  lock_info.l_start = offset;
  lock_info.l_len = 1;
  lock_info.l_type = type;
  lock_info.l_whence = SEEK_SET;
  int result;
  do {
    result = fcntl(vmem.fd, F_SETLKW, &lock_info);
  } while (result < 0 && errno == EINTR);
  return result;
}

bool lock_metapage() {
  return set_file_lock(0, F_WRLCK) == 0;
}

void unlock_metapage() {
  if (set_file_lock(0, F_UNLCK) < 0) {
    perror("vspace: bootstrap unlock");
    abort();
  }
}

void lock_refcount(vaddr_t vaddr) {
  if (set_file_lock(METABLOCK_SIZE + vaddr, F_WRLCK) < 0) {
    perror("vspace: reference-count lock");
    abort();
  }
}

void unlock_refcount(vaddr_t vaddr) {
  if (set_file_lock(METABLOCK_SIZE + vaddr, F_UNLCK) < 0) {
    perror("vspace: reference-count unlock");
    abort();
  }
}

static FileHeader create_file_header(SharedMemState state) {
  FileHeader header;
  std::memset(&header, 0, sizeof(header));
  header.magic = FILE_MAGIC;
  header.version = FILE_VERSION;
  header.init_state = state;
  header.header_size = sizeof(FileHeader);
  header.metablock_size = METABLOCK_SIZE;
  header.max_process = MAX_PROCESS;
  header.segment_size = SEGMENT_SIZE;
  header.max_segments = MAX_SEGMENTS;
  header.size_t_size = sizeof(size_t);
  header.pointer_size = sizeof(void *);
  header.pthread_mutex_size = sizeof(pthread_mutex_t);
  header.pthread_mutex_align = VSPACE_ALIGNOF(pthread_mutex_t);
  header.pthread_cond_size = sizeof(pthread_cond_t);
  header.pthread_cond_align = VSPACE_ALIGNOF(pthread_cond_t);
  header.layout_id = LAYOUT_ID;
  return header;
}

static bool compatible_file_header(const FileHeader &header) {
  FileHeader expected = create_file_header(SharedMemInitialized);
  return header.magic == expected.magic
      && header.version == expected.version
      && header.init_state == SharedMemInitialized
      && header.header_size == expected.header_size
      && header.metablock_size == expected.metablock_size
      && header.max_process == expected.max_process
      && header.segment_size == expected.segment_size
      && header.max_segments == expected.max_segments
      && header.size_t_size == expected.size_t_size
      && header.pointer_size == expected.pointer_size
      && header.pthread_mutex_size == expected.pthread_mutex_size
      && header.pthread_mutex_align == expected.pthread_mutex_align
      && header.pthread_cond_size == expected.pthread_cond_size
      && header.pthread_cond_align == expected.pthread_cond_align
      && header.layout_id == expected.layout_id;
}

Status init_metapage(bool create) {
  if (create && ftruncate(vmem.fd, METABLOCK_SIZE) < 0)
    return Status(ErrOS);
  if (!create && vmem.filesize() < METABLOCK_SIZE)
    return Status(ErrMMap);
  void *map = mmap(
      NULL, METABLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, vmem.fd, 0);
  if (map == MAP_FAILED)
    return Status(ErrMMap);
  vmem.metapage = (MetaPage *) map;
  if (create) {
    std::memset(map, 0, METABLOCK_SIZE);
    vmem.metapage->header = create_file_header(SharedMemInitializing);
    new (&vmem.metapage->allocator_lock) SharedMutex();
    new (&vmem.metapage->process_table_mutex) SharedMutex();
    new (&vmem.metapage->process_startup_condition) SharedCondition();
    for (int i = 0; i <= LOG2_SEGMENT_SIZE; i++)
      vmem.metapage->freelist[i] = VADDR_NULL;
    vmem.metapage->segment_count = 0;
    for (int i = 0; i < MAX_PROCESS; i++)
      new (&vmem.metapage->process_info[i]) ProcessInfo();
    vmem.metapage->header.init_state = SharedMemInitialized;
  } else if (!compatible_file_header(vmem.metapage->header)) {
    munmap(vmem.metapage, METABLOCK_SIZE);
    vmem.metapage = NULL;
    return Status(ErrGeneral);
  }
  return Status(ErrNone);
}

EventId join_selection(int event_index) {
  if (vmem.current_process < 0)
    pthread_fatal("join_selection() without current process", EINVAL);
  ProcessInfo &info = vmem.metapage->process_info[vmem.current_process];
  WaitContext &context = info.wait_context;
  context.notify_mutex.lock();
  if (info.slot_state != ProcessRunning || info.pid != getpid()
      || context.state != WaitIdle) {
    context.notify_mutex.unlock();
    pthread_fatal("second active VSpace wait", EBUSY);
  }
  context.sequence_id++;
  context.selected_event = -1;
  context.state = WaitActive;
  EventId id = { vmem.current_process, info.process_incarnation,
      context.sequence_id, event_index };
  context.notify_mutex.unlock();
  return id;
}

bool try_select(const EventId &id) {
  if (id.process_slot < 0 || id.process_slot >= MAX_PROCESS)
    return false;
  ProcessInfo &info = vmem.metapage->process_info[id.process_slot];
  WaitContext &context = info.wait_context;
  context.notify_mutex.lock();
  bool selected = info.slot_state == ProcessRunning
      && info.process_incarnation == id.process_incarnation
      && context.sequence_id == id.wait_sequence_id
      && context.state == WaitActive;
  if (selected) {
    context.selected_event = id.event_index;
    context.state = WaitSelected;
    context.notify_condition.signal();
  }
  context.notify_mutex.unlock();
  return selected;
}

int await_selection(const EventId &id) {
  ProcessInfo &info = vmem.metapage->process_info[id.process_slot];
  WaitContext &context = info.wait_context;
  context.notify_mutex.lock();
  while (context.sequence_id == id.wait_sequence_id
      && context.state == WaitActive)
    context.notify_condition.wait(context.notify_mutex);
  if (context.sequence_id != id.wait_sequence_id
      || context.state != WaitSelected) {
    context.notify_mutex.unlock();
    pthread_fatal("invalid wait-context transition", EINVAL);
  }
  int result = context.selected_event;
  context.notify_mutex.unlock();
  return result;
}

void leave_selection(const EventId &id) {
  ProcessInfo &info = vmem.metapage->process_info[id.process_slot];
  WaitContext &context = info.wait_context;
  context.notify_mutex.lock();
  if (context.sequence_id != id.wait_sequence_id
      || context.state != WaitSelected) {
    context.notify_mutex.unlock();
    pthread_fatal("invalid wait-context for leave_selection()", EINVAL);
  }
  context.state = WaitIdle;
  context.selected_event = -1;
  context.notify_mutex.unlock();
}

} // namespace internals

pid_t fork_process() {
  using namespace internals;
  MetaPage *metapage = vmem.metapage;
  metapage->process_table_mutex.lock();
  int slot = -1;
  size_t reserved_incarnation = 0;
  for (int p = 0; p < MAX_PROCESS; p++) {
    ProcessInfo &info = metapage->process_info[p];
    if (info.slot_state == ProcessUnused) {
      slot = p;
      info.wait_context.notify_mutex.lock();
      info.slot_state = ProcessStarting;
      reserved_incarnation = ++info.process_incarnation;
      info.startup_acknowledged = false;
      info.pid = 0;
      info.wait_context.notify_mutex.unlock();
      break;
    }
  }
  metapage->process_table_mutex.unlock();
  if (slot < 0)
    return -1;

  pid_t pid = fork();
  if (pid < 0) {
    metapage->process_table_mutex.lock();
    ProcessInfo &info = metapage->process_info[slot];
    info.wait_context.notify_mutex.lock();
    if (info.slot_state == ProcessStarting
        && info.process_incarnation == reserved_incarnation)
      info.slot_state = ProcessUnused;
    info.wait_context.notify_mutex.unlock();
    metapage->process_table_mutex.unlock();
    return -1;
  }
  if (pid == 0) {
    vmem.current_process = slot;
    metapage->process_table_mutex.lock();
    ProcessInfo &info = metapage->process_info[slot];
    if (info.slot_state != ProcessStarting
        || info.process_incarnation != reserved_incarnation)
      pthread_fatal("invalid fork slot reservation", EINVAL);
    info.wait_context.notify_mutex.lock();
    info.pid = getpid();
    info.slot_state = ProcessRunning;
    info.wait_context.notify_mutex.unlock();
    metapage->process_startup_condition.broadcast();
    while (!info.startup_acknowledged
        && info.process_incarnation == reserved_incarnation)
      metapage->process_startup_condition.wait(
          metapage->process_table_mutex);
    metapage->process_table_mutex.unlock();
    return 0;
  }

  metapage->process_table_mutex.lock();
  ProcessInfo &info = metapage->process_info[slot];
  while (info.slot_state == ProcessStarting
      && info.process_incarnation == reserved_incarnation)
    metapage->process_startup_condition.wait(
        metapage->process_table_mutex);
  if (info.slot_state != ProcessRunning
      || info.process_incarnation != reserved_incarnation) {
    metapage->process_table_mutex.unlock();
    pthread_fatal("invalid child startup transition", EINVAL);
  }
  info.startup_acknowledged = true;
  metapage->process_startup_condition.broadcast();
  metapage->process_table_mutex.unlock();
  return pid;
}

size_t Semaphore::value() {
  _lock.lock();
  size_t result = _value;
  _lock.unlock();
  return result;
}

void Semaphore::post() {
  _lock.lock();
  while (_head != _tail) {
    internals::EventId id = _waiting[_head];
    next(_head);
    if (internals::try_select(id)) {
      _lock.unlock();
      return;
    }
  }
  _value++;
  _lock.unlock();
}

bool Semaphore::try_wait() {
  bool result = false;
  _lock.lock();
  if (_value > 0) {
    _value--;
    result = true;
  }
  _lock.unlock();
  return result;
}

void Semaphore::wait() {
  internals::EventId id = internals::join_selection(0);
  start_wait(id);
  internals::await_selection(id);
  stop_wait(id);
  internals::leave_selection(id);
}

internals::EventSelection Semaphore::start_wait(
    const internals::EventId &id) {
  _lock.lock();
  if (_value > 0) {
    if (internals::try_select(id)) {
      _value--;
      _lock.unlock();
      return internals::EventSelected;
    }
    _lock.unlock();
    return internals::EventAlreadySelected;
  }
  for (int i = _head; i != _tail; next(i)) {
    if (_waiting[i].process_slot == id.process_slot
        && _waiting[i].process_incarnation == id.process_incarnation
        && _waiting[i].wait_sequence_id == id.wait_sequence_id) {
      _lock.unlock();
      return internals::EventAlreadyQueued;
    }
  }
  int new_tail = _tail;
  next(new_tail);
  if (new_tail == _head) {
    _lock.unlock();
    internals::pthread_fatal("semaphore waiter queue full", EOVERFLOW);
  }
  _waiting[_tail] = id;
  _tail = new_tail;
  _lock.unlock();
  return internals::EventQueued;
}

bool Semaphore::stop_wait(const internals::EventId &id) {
  _lock.lock();
  for (int i = _head; i != _tail; next(i)) {
    if (_waiting[i] == id) {
      int source = i;
      int destination = i;
      next(source);
      while (source != _tail) {
        _waiting[destination] = _waiting[source];
        destination = source;
        next(source);
      }
      _tail = destination;
      _lock.unlock();
      return true;
    }
  }
  _lock.unlock();
  return false;
}

void EventSet::add(Event *event) {
  assert(event != NULL);
  for (Event *existing = _head; existing; existing = existing->_next) {
    if (existing == event)
      return;
  }
  event->_next = NULL;
  event->_registered = false;
  if (_head == NULL) {
    _head = _tail = event;
  } else {
    _tail->_next = event;
    _tail = event;
  }
}

int EventSet::wait() {
  if (_head == NULL)
    internals::pthread_fatal("empty EventSet", EINVAL);
  internals::EventId wait_id = internals::join_selection(0);
  int index = 0;
  for (Event *event = _head; event; event = event->_next, index++) {
    event->_id = wait_id;
    event->_id.event_index = index;
    internals::EventSelection registration =
        event->start_listen(event->_id);
    event->_registered = registration == internals::EventQueued;
    if (registration != internals::EventQueued
        && registration != internals::EventAlreadyQueued)
      break;
  }
  int result = internals::await_selection(wait_id);
  for (Event *event = _head; event; event = event->_next) {
    if (event->_registered) {
      event->stop_listen(event->_id);
      event->_registered = false;
    }
  }
  internals::leave_selection(wait_id);
  return result;
}

} // namespace vspace
