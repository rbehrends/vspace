#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// vspace is a C++ library designed to 

namespace vspace {

namespace internals {

typedef size_t segaddr_t;
typedef size_t vaddr_t;

const segaddr_t SEGADDR_NULL = ~(segaddr_t)0;
const vaddr_t VADDR_NULL = ~(segaddr_t)0;

void init_flock_struct(struct flock &lock_info, size_t offset, size_t len,
                       bool lock) {
  lock_info.l_start = offset;
  lock_info.l_len = len;
  lock_info.l_pid = 0;
  lock_info.l_type = lock ? F_WRLCK : F_UNLCK;
  lock_info.l_whence = SEEK_SET;
}

void lock_file(int fd, size_t offset, size_t len = 1) {
  struct flock lock_info;
  init_flock_struct(lock_info, offset, len, true);
  fcntl(fd, F_SETLK, &lock_info);
}

void unlock_file(int fd, size_t offset, size_t len = 1) {
  struct flock lock_info;
  init_flock_struct(lock_info, offset, len, false);
  fcntl(fd, F_SETLK, &lock_info);
}

void lock_metapage();
void unlock_metapage();
void init_metapage();

struct Block;
struct MetaPage;
struct Process;

struct MetaPage {
  vaddr_t freelist[LOG2_SEGMENT_SIZE + 1];
  char valid_segment[MAX_SEGMENTS];
  int segment_count;
};

struct VMem {
  MetaPage *metapage;
  int fd;
  vaddr_t *freelist; // reference to metapage information
  VSeg segments[MAX_SEGMENTS];
  Process *processes[MAX_PROCESS];
  inline VSeg segment(vaddr_t vaddr) {
    return segments[vaddr >> LOG2_SEGMENT_SIZE];
  }
  inline segaddr_t segaddr(vaddr_t vaddr) {
    if (vaddr == VADDR_NULL)
      return SEGADDR_NULL;
    return vaddr & SEGMENT_MASK;
  }
  size_t filesize() {
    struct stat stat;
    fstat(fd, &stat);
    return stat.st_size;
  }
  void init(int fd) {
    this->fd = fd;
    for (int i = 0; i < MAX_SEGMENTS; i++)
      segments[i] = VSeg(NULL);
    lock_metapage();
    if (filesize() == 0) {
      init_metapage();
    }
    unlock_metapage();
    freelist = metapage->freelist;
  }
  inline Block *block_ptr(vaddr_t vaddr) {
    if (vaddr == VADDR_NULL)
      return NULL;
    return (Block *)(segment(vaddr).base + segaddr(vaddr));
  }
  void *mmap_segment(int seg) {
    lock_metapage();
    void *result = mmap(NULL, SEGMENT_SIZE, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, seg * SEGMENT_SIZE);
    unlock_metapage();
    return NULL;
  }
  void ensure_is_mapped(vaddr_t vaddr) {
    int seg = vaddr >> LOG2_SEGMENT_SIZE;
    if (segments[seg].base != NULL)
      return;
    segments[seg] = mmap_segment(seg);
  }
  void *to_ptr(vaddr_t vaddr) {
    ensure_is_mapped(vaddr);
    return segment(vaddr).ptr(segaddr(vaddr));
  }
  void *map_segments(int lastseg) {
    if (!metapage->valid_segment[lastseg]) {
      ftruncate(fd, (lastseg + 1) * SEGMENT_SIZE);
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
};

static VMem vmem;

struct Block {
  vaddr_t prev;
  vaddr_t next;
  bool is_free() {
    return (prev & 3) == 1;
  }
  int level() {
    return (int)(prev >> 2);
  }
  void mark_as_allocated(int level) {
    prev = (level << 2) | 1;
  }
};

struct ProcessInfo {
  int pipe_fd;
  char fifo_path[256 - sizeof(int)];
};

static const int MAX_PROCESS = 64;
static const size_t METABLOCK_SIZE = 128 * 1024; // 128 KB
static const int LOG2_SEGMENT_SIZE = 28;         // 256 MB
static const size_t MAX_SEGMENTS = 1024;         // 256 GB
static const size_t SEGMENT_SIZE = 1 << LOG2_SEGMENT_SIZE;
static const size_t SEGMENT_MASK = (SEGMENT_SIZE - 1);

struct VSeg {
  unsigned char *base;
  inline Block *block_ptr(segaddr_t addr) {
    return (Block *)(base + addr);
  }
  inline void *ptr(segaddr_t addr) {
    return (void *)(base + addr);
  }
  VSeg() : base(NULL) {
  }
  VSeg(void *base) : base((unsigned char *)base) {
  }
};

void lock_metapage() {
  lock_file(vmem.fd, 0);
}

void unlock_metapage() {
  unlock_file(vmem.fd, 0);
}

void init_metapage() {
  ftruncate(vmem.fd, METABLOCK_SIZE);
  vmem.metapage = (MetaPage *)mmap(NULL, METABLOCK_SIZE, vmem.fd,
                                   PROT_READ | PROT_WRITE, MAP_SHARED, 0);
  for (int i = 0; i <= LOG2_SEGMENT_SIZE; i++) {
    vmem.metapage->freelist[i] = VADDR_NULL;
  }
  for (int i = 0; i < MAX_SEGMENTS; i++) {
    vmem.metapage->valid_segment[i] = 0;
  }
  vmem.metapage->segment_count = 0;
}

static int find_level(size_t size) {
  int level = 0;
  while ((1 << (level + 8)) <= size)
    level += 8;
  while ((1 << level) < size)
    level++;
  return level;
}

static segaddr_t find_buddy(segaddr_t addr, int level) {
  return addr ^ (1 << level);
}

static bool is_free(VSeg seg, segaddr_t addr) {
  Block *block = seg.block_ptr(addr);
  return block->is_free();
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
  size_t alloc_size;
  if (size <= sizeof(segaddr_t))
    alloc_size = sizeof(Block);
  else
    alloc_size += sizeof(Block);
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
      vmem.block_ptr(vmem.freelist[flevel])->prev == SEGADDR_NULL;
    segaddr_t blockaddr2 = blockaddr + (1 << (flevel - 1));
    Block *block2 = vmem.block_ptr(blockaddr2);
    block2->next = block->next;
    block2->prev = blockaddr;
    block->next = blockaddr2;
    flevel--;
  }
  Block *block = vmem.block_ptr(vmem.freelist[level]);
  segaddr_t result = vmem.freelist[level];
  if (size <= sizeof(segaddr_t))
    result += sizeof(segaddr_t);
  else
    result += sizeof(Block);
  vmem.freelist[level] = block->next;
  block->mark_as_allocated(level);
  return result;
};

}; // namespace internals

using namespace internals;

template <typename T> struct VRef {
private:
  vaddr_t vaddr;
  void *to_ptr() {
    return vmem.to_ptr(vaddr);
  }

public:
  operator bool() {
    return pos >= 0;
  }
  T &operator*() {
    return *(T *)to_ptr();
  }
  T *operator->() {
    return (T *)to_ptr();
  }
};

class Mutex {
private:
  pid_t _owner;
  size_t _count;
  size_t _offset;
  static pid_t pid() {
    static pid_t result;
    static bool init = false;
    if (!init)
      result = getpid();
    return result;
  }

public:
  void lock() {
    if (_owner == pid()) {
      _count++;
      return;
    }
    lock_file(vmem.fd, _offset);
  }
  void unlock() {
    if (_owner == pid()) {
      _count--;
      if (_count == 0) {
        unlock_file(vmem.fd, _offset);
      }
    }
  }
};

class Semaphore {
private:
  int _owner;
  int _nwaiting;
  int _waiting[MAX_PROCESS];
};

}; // namespace vspace
