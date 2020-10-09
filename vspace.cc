#include "vspace.h"

namespace vspace {
namespace internals {

size_t config[4]
    = { METABLOCK_SIZE, MAX_PROCESS, SEGMENT_SIZE, MAX_SEGMENTS };

VMem VMem::vmem_global;

size_t VMem::filesize() {
  struct stat stat;
  fstat(fd, &stat);
  return stat.st_size;
}

void VMem::init(int fd) {
  this->fd = fd;
  for (int i = 0; i < MAX_SEGMENTS; i++)
    segments[i] = VSeg(NULL);
  for (int i = 0; i < MAX_PROCESS; i++) {
    int channel[2];
    pipe(channel);
    channels[i].fd_read = channel[0];
    channels[i].fd_write = channel[1];
  }
  lock_metapage();
  init_metapage(filesize() == 0);
  unlock_metapage();
  freelist = metapage->freelist;
}

void VMem::init() {
  FILE *fp = tmpfile();
  init(fileno(fp));
  current_process = 0;
  metapage->process_info[0].pid = getpid();
}

bool VMem::init(const char *path) {
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return false;
  init(fd);
  lock_metapage();
  // TODO: enter process in meta table
  unlock_metapage();
  return true;
}

void *VMem::mmap_segment(int seg) {
  lock_metapage();
  void *result = mmap(NULL, SEGMENT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
      fd, METABLOCK_SIZE + seg * SEGMENT_SIZE);
  if (result == MAP_FAILED)
    perror("mmap");
  unlock_metapage();
  return result;
}

void VMem::add_segment() {
  int seg = metapage->segment_count++;
  ftruncate(fd, METABLOCK_SIZE + metapage->segment_count * SEGMENT_SIZE);
  void *map_addr = mmap_segment(seg);
  segments[seg] = VSeg(map_addr);
  Block *top = block_ptr(seg * SEGMENT_SIZE);
  top->next = freelist[LOG2_SEGMENT_SIZE];
  top->prev = VADDR_NULL;
  freelist[LOG2_SEGMENT_SIZE] = seg * SEGMENT_SIZE;
}

static void lock_allocator() {
  lock_file(vmem.fd, offsetof(MetaPage, freelist));
}

static void unlock_allocator() {
  unlock_file(vmem.fd, offsetof(MetaPage, freelist));
}

static void print_freelists() {
  for (int i = 0; i <= LOG2_SEGMENT_SIZE; i++) {
    vaddr_t vaddr = vmem.freelist[i];
    if (vaddr != VADDR_NULL) {
      printf("%2d: %ld", i, vaddr);
      vaddr_t prev = block_ptr(vaddr)->prev;
      if (prev != VADDR_NULL) {
        printf("(%ld)", prev);
      }
      assert(block_ptr(vaddr)->prev == VADDR_NULL);
      for (;;) {
        vaddr_t last_vaddr = vaddr;
        Block *block = block_ptr(vaddr);
        vaddr = block->next;
        if (vaddr == VADDR_NULL)
          break;
        printf(" -> %ld", vaddr);
        vaddr_t prev = block_ptr(vaddr)->prev;
        if (prev != last_vaddr) {
          printf("(%ld)", prev);
        }
      }
      printf("\n");
    }
  }
  fflush(stdout);
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
      assert(vmem.freelist[level] == buddy);
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
  lock_allocator();
  size_t alloc_size = size + offsetof(Block, data);
  int level = find_level(alloc_size);
  int flevel = level;
  while (flevel < LOG2_SEGMENT_SIZE && vmem.freelist[flevel] == VADDR_NULL)
    flevel++;
  if (vmem.freelist[flevel] == VADDR_NULL) {
    vmem.add_segment();
  }
  vmem.ensure_is_mapped(vmem.freelist[flevel]);
  while (flevel > level) {
    // get and split a block
    vaddr_t blockaddr = vmem.freelist[flevel];
    assert((blockaddr & ((1 << flevel) - 1)) == 0);
    Block *block = vmem.block_ptr(blockaddr);
    vmem.freelist[flevel] = block->next;
    if (vmem.freelist[flevel] != VADDR_NULL)
      vmem.block_ptr(vmem.freelist[flevel])->prev = VADDR_NULL;
    vaddr_t blockaddr2 = blockaddr + (1 << (flevel - 1));
    Block *block2 = vmem.block_ptr(blockaddr2);
    flevel--;
    block2->next = vmem.freelist[flevel];
    block2->prev = blockaddr;
    block->next = blockaddr2;
    block->prev = VADDR_NULL;
    // block->prev == VADDR_NULL already.
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
  return result;
}

void init_flock_struct(
    struct flock &lock_info, size_t offset, size_t len, bool lock) {
  lock_info.l_start = offset;
  lock_info.l_len = len;
  lock_info.l_pid = 0;
  lock_info.l_type = lock ? F_WRLCK : F_UNLCK;
  lock_info.l_whence = SEEK_SET;
}

void lock_file(int fd, size_t offset, size_t len) {
  struct flock lock_info;
  init_flock_struct(lock_info, offset, len, true);
  fcntl(fd, F_SETLKW, &lock_info);
}

void unlock_file(int fd, size_t offset, size_t len) {
  struct flock lock_info;
  init_flock_struct(lock_info, offset, len, false);
  fcntl(fd, F_SETLKW, &lock_info);
}

void lock_metapage() {
  lock_file(vmem.fd, 0);
}

void unlock_metapage() {
  unlock_file(vmem.fd, 0);
}

void init_metapage(bool create) {
  if (create)
    ftruncate(vmem.fd, METABLOCK_SIZE);
  vmem.metapage = (MetaPage *) mmap(
      NULL, METABLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, vmem.fd, 0);
  if (create) {
    memcpy(vmem.metapage->config_header, config, sizeof(config));
    for (int i = 0; i <= LOG2_SEGMENT_SIZE; i++) {
      vmem.metapage->freelist[i] = VADDR_NULL;
    }
    vmem.metapage->segment_count = 0;
  } else {
    assert(memcmp(vmem.metapage->config_header, config, sizeof(config)) != 0);
  }
}

static void lock_process(int processno) {
  lock_file(vmem.fd,
      offsetof(MetaPage, process_info)
          + sizeof(ProcessInfo) * vmem.current_process);
}

static void unlock_process(int processno) {
  unlock_file(vmem.fd,
      offsetof(MetaPage, process_info)
          + sizeof(ProcessInfo) * vmem.current_process);
}

static ProcessInfo &process_info(int processno) {
  return vmem.metapage->process_info[processno];
}

bool send_signal(int processno, ipc_signal_t sig) {
  lock_process(processno);
  if (process_info(processno).sigstate != Waiting) {
    unlock_process(processno);
    return false;
  }
  if (processno == vmem.current_process) {
    process_info(processno).sigstate = Accepted;
    process_info(processno).signal = sig;
  } else {
    process_info(processno).sigstate = Pending;
    process_info(processno).signal = sig;
    int fd = vmem.channels[processno].fd_write;
    char buf[1] = { 0 };
    write(fd, buf, 1);
  }
  unlock_process(processno);
  return true;
}

ipc_signal_t check_signal(bool resume) {
  ipc_signal_t result;
  lock_process(vmem.current_process);
  SignalState sigstate = process_info(vmem.current_process).sigstate;
  switch (sigstate) {
    case Waiting:
    case Pending: {
      int fd = vmem.channels[vmem.current_process].fd_read;
      char buf[1];
      unlock_process(vmem.current_process);
      read(fd, buf, 1);
      if (sigstate == Waiting) {
        lock_process(vmem.current_process);
        process_info(vmem.current_process).sigstate
            = resume ? Waiting : Accepted;
        unlock_process(vmem.current_process);
      }
      break;
    }
    case Accepted:
      result = process_info(vmem.current_process).signal;
      if (resume)
        process_info(vmem.current_process).sigstate = Waiting;
      unlock_process(vmem.current_process);
      break;
  }
  return process_info(vmem.current_process).signal;
}

void accept_signals() {
  lock_process(vmem.current_process);
  process_info(vmem.current_process).sigstate = Waiting;
  unlock_process(vmem.current_process);
}

ipc_signal_t wait_signal() {
  return check_signal(true);
}

} // namespace internals

pid_t fork_process() {
  using namespace internals;
  lock_metapage();
  for (int p = 0; p < MAX_PROCESS; p++) {
    if (vmem.metapage->process_info[p].pid == 0) {
      pid_t pid = fork();
      if (pid < 0) {
        // error
        return -1;
      } else if (pid == 0) {
        // child process
        int parent = vmem.current_process;
        vmem.current_process = p;
        lock_metapage();
        vmem.metapage->process_info[p].pid = getpid();
        unlock_metapage();
        send_signal(parent);
      } else {
        // parent process
        unlock_metapage();
        wait_signal();
        // child has unlocked metapage, so we don't need to.
      }
      return pid;
    }
  }
  unlock_metapage();
  return -1;
}

} // namespace vspace