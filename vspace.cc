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
  lock_file(vmem.fd, offsetof(MetaPage, freelist));
}

void vmem_free(vaddr_t vaddr) {
  lock_allocator();
  vaddr -= sizeof(Block);
  vmem.ensure_is_mapped(vaddr);
  VSeg seg = vmem.segment(vaddr);
  segaddr_t addr = vmem.segaddr(vaddr);
  int level = seg.block_ptr(addr)->level();
  segaddr_t buddy = find_buddy(addr, level);
  bool freed = false;
  while (level < LOG2_SEGMENT_SIZE && seg.is_free(buddy)) {
    // buddy is free.
    // remove buddy from freelist
    Block *block = seg.block_ptr(buddy);
    if (block->prev == VADDR_NULL) {
      // head of free list
      vmem.freelist[level] = block->next;
    } else {
      // inner node
      Block *prev = vmem.block_ptr(block->prev);
      Block *next = vmem.block_ptr(block->next);
      if (prev)
        prev->next = block->next;
      if (next)
        next->prev = block->prev;
    }
    level++;
    // insert joined block + buddy one level up
    if (buddy < addr)
      addr = buddy;
    buddy = find_buddy(addr, level);
    block = seg.block_ptr(addr);
    block->prev = VADDR_NULL;
    block->next = vmem.freelist[level];
    vmem.freelist[level] = addr;
    freed = true;
  }
  // Has the block not yet been freed as part of being
  // merged? If not, free it now.
  if (!freed) {
    Block *block = seg.block_ptr(addr);
    block->prev = VADDR_NULL;
    block->next = vmem.freelist[level];
    vmem.freelist[level] = addr;
  }
  unlock_allocator();
}

vaddr_t vmem_alloc(size_t size) {
  lock_allocator();
  size_t alloc_size = size + sizeof(Block);
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
    Block *block = vmem.block_ptr(blockaddr);
    vmem.freelist[flevel] = block->next;
    if (vmem.freelist[flevel] != VADDR_NULL)
      vmem.block_ptr(vmem.freelist[flevel])->prev = VADDR_NULL;
    segaddr_t blockaddr2 = blockaddr + (1 << (flevel - 1));
    Block *block2 = vmem.block_ptr(blockaddr2);
    flevel--;
    block2->next = vmem.freelist[flevel];
    block2->prev = blockaddr;
    block->next = blockaddr2;
    // block->prev == VADDR_NULL already.
    vmem.freelist[flevel] = blockaddr;
  }
  Block *block = vmem.block_ptr(vmem.freelist[level]);
  vaddr_t vaddr = vmem.freelist[level];
  vaddr_t result = vaddr + sizeof(Block);
  vmem.freelist[level] = block->next;
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
  fcntl(fd, F_SETLK, &lock_info);
}

void unlock_file(int fd, size_t offset, size_t len) {
  struct flock lock_info;
  init_flock_struct(lock_info, offset, len, false);
  fcntl(fd, F_SETLK, &lock_info);
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

void send_signal(int processno) {
  static char buf[1] = "";
  // TODO: init channels[] on demand.
  int fd = vmem.channels[processno].fd_write;
  write(fd, buf, 1);
}

void wait_signal() {
  char buf[1];
  int fd = vmem.channels[vmem.current_process].fd_write;
  read(fd, buf, 1);
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
      } else if (pid == 0) {
        // child process
        int parent = vmem.current_process;
        vmem.current_process = p;
        vmem.metapage->process_info[p].pid = getpid();
        unlock_metapage();
        send_signal(parent);
      } else {
        // parent process
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