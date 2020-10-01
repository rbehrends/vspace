#include "vspace.h"

namespace vspace { namespace internals {

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
    lock_metapage();
    init_metapage(filesize() == 0);
    unlock_metapage();
    freelist = metapage->freelist;
  }
  void VMem::init() {
    FILE *fp = tmpfile();
    init(fileno(fp));
    int channel[2];
    pipe(channel);
    metapage->process_info[0].pid = getpid();
    metapage->process_info[0].pipe_fd = channel[1];
    current_process = getpid();
    signal_fd = channel[0];
    fcntl(signal_fd, FD_CLOEXEC);
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
    void *result = mmap(NULL, SEGMENT_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, METABLOCK_SIZE + seg * SEGMENT_SIZE);
    if (result == MAP_FAILED)
      perror("mmap");
    unlock_metapage();
    return NULL;
  }
  void VMem::map_segments(int lastseg) {
    if (!metapage->valid_segment[lastseg]) {
      ftruncate(fd, METABLOCK_SIZE + (lastseg + 1) * SEGMENT_SIZE);
      while (metapage->segment_count <= lastseg) {
        int seg = ++metapage->segment_count;
        metapage->valid_segment[seg] = 1;
        void *map_addr = mmap_segment(seg);
        segments[seg] = VSeg(map_addr);
        Block *top = block_ptr(seg * SEGMENT_SIZE);
        top->next = freelist[LOG2_SEGMENT_SIZE];
        top->prev = VADDR_NULL;
        freelist[LOG2_SEGMENT_SIZE] = seg * SEGMENT_SIZE;
      }
    }
  }


void vmem_free(vaddr_t vaddr) {
  VSeg seg = vmem.segment(vaddr);
  segaddr_t addr = vmem.segaddr(vaddr);
  int level = seg.block_ptr(addr)->level();
  segaddr_t buddy = find_buddy(addr, level);
  while (level < LOG2_SEGMENT_SIZE && is_free(seg, buddy)) {
    // buddy is free.
    Block *block = seg.block_ptr(buddy);
    if (block->prev == VADDR_NULL) {
      vmem.freelist[level] = block->next;
    } else {
      Block *prev = vmem.block_ptr(block->prev);
      Block *next = vmem.block_ptr(block->next);
      if (prev)
        prev->next = block->next;
      if (next)
        next->prev = block->prev;
    }
    level++;
    if (buddy < addr)
      addr = buddy;
  }
  Block *block = seg.block_ptr(addr);
  block->prev = VADDR_NULL;
  block->next = vmem.freelist[level];
  vmem.freelist[level] = addr;
}

vaddr_t vmem_alloc(size_t size) {
  size_t alloc_size = size + sizeof(Block);
  int level = find_level(alloc_size);
  int flevel = level;
  while (flevel < LOG2_SEGMENT_SIZE && vmem.freelist[flevel] < 0)
    flevel++;
  if (vmem.freelist[flevel] == VADDR_NULL) {

    // TODO: allocate new segment
  }
  while (flevel > level) {
    // get and split a block
    vaddr_t blockaddr = vmem.freelist[flevel];
    Block *block = vmem.block_ptr(blockaddr);
    vmem.freelist[flevel] = block->next;
    if (vmem.freelist[flevel] >= 0)
      vmem.block_ptr(vmem.freelist[flevel])->prev = SEGADDR_NULL;
    segaddr_t blockaddr2 = blockaddr + (1 << (flevel - 1));
    Block *block2 = vmem.block_ptr(blockaddr2);
    block2->next = block->next;
    block2->prev = blockaddr;
    block->next = blockaddr2;
    flevel--;
  }
  Block *block = vmem.block_ptr(vmem.freelist[level]);
  vaddr_t vaddr = vmem.freelist[level];
  vaddr_t result = vaddr + sizeof(Block);
  vmem.freelist[level] = block->next;
  block->mark_as_allocated(vaddr, level);
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
    for (int i = 0; i < MAX_SEGMENTS; i++) {
      vmem.metapage->valid_segment[i] = 0;
    }
    vmem.metapage->segment_count = 0;
  } else {
    assert(memcmp(vmem.metapage->config_header, config, sizeof(config)) != 0);
  }
}

void send_signal(int processno) {
  static char buf[1] = "";
  // TODO: init processes[] on demand.
  write(vmem.processes[processno]->fd, buf, 1);
}

void wait_signal() {
  char buf[1];
  read(vmem.signal_fd, buf, 1);
}

} // namespace internals

ForkResult fork_process() {
  using namespace internals;
  lock_metapage();
  for (int i = 0; i < MAX_PROCESS; i++) {
    if (vmem.metapage->process_info[i].pid == 0) {
      int channel[2];
      pipe(channel);
      fcntl(channel[1], FD_CLOEXEC);
      vmem.metapage->process_info[i].pipe_fd = channel[1];
      pid_t pid = fork();
      if (pid < 0) {
        // error
        return ForkResult(FORK_FAILED, -1);
      } else if (pid == 0) {
        // child process
        int parent = vmem.current_process;
        vmem.current_process = i;
        vmem.metapage->process_info[i].pid = getpid();
        vmem.signal_fd = channel[0];
        unlock_metapage();
        send_signal(parent);
        return ForkResult(CHILD_PROCESS, getpid());
      } else {
        // parent process
        close(channel[0]);
        wait_signal();
        // child has unlocked metapage, so we don't need to.
        return ForkResult(PARENT_PROCESS, pid);
      }
    }
    return ForkResult(FORK_FAILED, -1);
  }
  unlock_metapage();
  return ForkResult(FORK_FAILED, -1);
}

} // namespace vspace