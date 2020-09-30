#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// vspace is a C++ library designed to allow processes in a multi-process
// environment to interoperate via mmapped shared memory. The library
// provides facilities for shared memory allocation and deallocation,
// shared mutexes, semaphores, queues, lists, and hash tables.
//
// The underlying file is organized starting with a block containing meta
// information such as free lists and process information necessary for
// IPC, followed by one or more segments of mmapped memory. Each address
// within the file is represented via its offset from the beginning of
// the first segment.
//
// These offsets are wrapped within the VRef<T> class, which works like a T*
// pointer, but transparently maps file offsets to memory locations.

namespace vspace {

namespace internals {

  typedef size_t segaddr_t;
  typedef size_t vaddr_t;

  const segaddr_t SEGADDR_NULL = ~(segaddr_t) 0;
  const vaddr_t VADDR_NULL = ~(segaddr_t) 0;

  static const int MAX_PROCESS = 64;
  static const size_t METABLOCK_SIZE = 128 * 1024; // 128 KB
  static const int LOG2_SEGMENT_SIZE = 28; // 256 MB
  static const int LOG2_MAX_SEGMENTS = 10; // 256 GB
  static const size_t MAX_SEGMENTS = 1 << LOG2_MAX_SEGMENTS;
  static const size_t SEGMENT_SIZE = 1 << LOG2_SEGMENT_SIZE;
  static const size_t SEGMENT_MASK = (SEGMENT_SIZE - 1);

  size_t config[4]
      = { METABLOCK_SIZE, MAX_PROCESS, SEGMENT_SIZE, MAX_SEGMENTS };

  void init_flock_struct(
      struct flock &lock_info, size_t offset, size_t len, bool lock) {
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
  void init_metapage(bool create);

  struct Block;
  struct MetaPage;
  struct Process;

  struct ProcessInfo {
    // pipe_fd < 0 implies that fifo_path is valid and contains a
    // zero-terminated path for a POSIX fifo.
    pid_t pid;
    int pipe_fd;
    char fifo_path[256 - sizeof(int) - sizeof(pid_t)];
  };

  struct MetaPage {
    size_t config_header[4];
    vaddr_t freelist[LOG2_SEGMENT_SIZE + 1];
    char valid_segment[MAX_SEGMENTS];
    int segment_count;
    ProcessInfo process_info[MAX_PROCESS];
  };

  struct Process {
    int number;
    int fd;
    Process(int number, ProcessInfo info);
  };

  struct VMem {
    MetaPage *metapage;
    int fd;
    int current_process; // index into process table
    int signal_fd; // fd where the current process receives control information
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
      init_metapage(filesize() == 0);
      unlock_metapage();
      freelist = metapage->freelist;
    }
    void init() {
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
    bool init(const char *path) {
      int fd = open(path, O_RDWR | O_CREAT, 0600);
      if (fd < 0)
        return false;
      init(fd);
      lock_metapage();
      // TODO: enter process in meta table
      unlock_metapage();
      return true;
    }
    inline Block *block_ptr(vaddr_t vaddr) {
      if (vaddr == VADDR_NULL)
        return NULL;
      return (Block *) (segment(vaddr).base + segaddr(vaddr));
    }
    void *mmap_segment(int seg) {
      lock_metapage();
      void *result = mmap(NULL, SEGMENT_SIZE, PROT_READ | PROT_WRITE,
          MAP_SHARED, fd, METABLOCK_SIZE + seg * SEGMENT_SIZE);
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
  };

  static VMem vmem;

  struct Block {
    // the lowest bits of prev encode whether we are looking at
    // an allocated or free block. For an allocared block, the
    // lowest bits are 01. For a free block, they are 00 (for a
    // null reference (== -1), they are 11.
    // For allocated blocks, the higher bits encode the segment
    // and the log2 of the block offset. This requires
    // LOG2_MAX_SEGMENTS + log2(sizeof(vaddr_t) * 8) + 2 bits.
    vaddr_t prev;
    vaddr_t next;
    bool is_free() {
      return (prev & 3) == 1;
    }
    int level() {
      return (int) (prev >> (LOG2_MAX_SEGMENTS + 2));
    }
    void mark_as_allocated(vaddr_t vaddr, int level) {
      vaddr_t bits = level;
      bits <<= LOG2_MAX_SEGMENTS;
      bits |= vaddr >> LOG2_SEGMENT_SIZE;
      bits <<= 2;
      bits |= 1;
      prev = bits;
    }
  };

  struct VSeg {
    unsigned char *base;
    inline Block *block_ptr(segaddr_t addr) {
      return (Block *) (base + addr);
    }
    inline void *ptr(segaddr_t addr) {
      return (void *) (base + addr);
    }
    VSeg() : base(NULL) {
    }
    VSeg(void *base) : base((unsigned char *) base) {
    }
  };

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
        NULL, METABLOCK_SIZE, vmem.fd, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
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
      if (memcmp(vmem.metapage->config_header, config, sizeof(config)) != 0)
        abort();
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
    vaddr_t vaddr = vmem.freelist[level];
    vaddr_t result;
    if (size <= sizeof(vaddr_t))
      result = vaddr + sizeof(vaddr_t);
    else
      result = vaddr + sizeof(Block);
    vmem.freelist[level] = block->next;
    block->mark_as_allocated(vaddr, level);
    return result;
  }

  vaddr_t allocated_ptr_to_vaddr(void *ptr, size_t size) {
    char *addr = (char *) ptr;
    if (size <= sizeof(vaddr_t))
      addr -= sizeof(vaddr_t);
    else
      addr -= sizeof(Block);
    vaddr_t info = ((Block *) addr)->prev;
    int seg = info & (MAX_SEGMENTS - 1);
    char *segstart = vmem.segments[seg].base;
    size_t offset = (char *) ptr - segstart;
    return (seg << LOG2_SEGMENT_SIZE) | offset;
  }

}; // namespace internals

template <typename T>
struct VRef {
private:
  vaddr_t vaddr;
  void *to_ptr() {
    return vmem.to_ptr(vaddr);
  }

public:
  VRef() : vaddr(VADDR_NULL) {
  }
  VRef(vaddr_t vaddr) : vaddr(vaddr) {
  }
  operator bool() {
    return pos >= 0;
  }
  VRef(void *ptr) {
    vaddr = allocated_ptr_to_vaddr(ptr);
  }
  T *as_ptr() {
    return (T *) to_ptr();
  }
  T &operator*() {
    return *(T *) to_ptr();
  }
  T *operator->() {
    return (T *) to_ptr();
  }
  VRef<T> &operator=(VRef<T> other) {
    vaddr = other.vaddr;
  }
  template <typename U>
  VRef<U> cast() {
    return VRef<U>(vaddr);
  }
  void free() {
    as_ptr->~T(); // explicitly call destructor
    vmem_free(vaddr);
    vaddr = VADDR_NULL;
  }
  void lock() {
    lock_file(vmem.fd, vaddr + METABLOCK_SIZE);
  }
  void unlock() {
    unlock_file(vmem.fd, vaddr + METABLOCK_SIZE);
  }
};

template <typename T>
VRef<T> vnull() {
  return
}

template <typename T>
VRef<T> vnew() {
  VRref<T> result = VRef<T>(vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T();
  return result;
}

template <typename T>
VRef<T> vnew_uninitialized() {
  VRref<T> result = VRef<T>(vmem_alloc(sizeof(T)));
  return result;
}

template <typename T, typename Arg>
VRef<T> vnew(Arg arg) {
  VRref<T> result = VRef<T>(vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg);
  return result;
}

template <typename T, typename Arg1, typename Arg2>
VRef<T> vnew(Arg1 arg1, Arg2 arg2) {
  VRref<T> result = VRef<T>(vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg1, arg2);
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  VRref<T> result = VRef<T>(vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg1, arg2, arg3);
  return result;
}

class VStringHeader {
private:
  internals::vaddr_t _buffer;
  size_t _len;

public:
  VStringHeader(const char *s) {
    _len = strlen(s);
    _buffer = internals::vmem_alloc(_len + 1);
    strcpy((char *) internals::vmem.to_ptr(_buffer), s);
  }
  VStringHeader(const char *s, size_t len) {
    _len = len;
    _buffer = internals::vmem_alloc(len + 1);
    strcpy((char *) internals::vmem.to_ptr(_buffer), s);
  }
  ~VStringHeader() {
    internals::vmem_free(_buffer);
  }
  size_t len() {
    return _len;
  }
  const char *str() {
    return (const char *) internals::vmem.to_ptr(_buffer);
  }
};

typedef VRef<VStringHeader> VString;

enum ForkResultType { FORK_FAILED, CHILD_PROCESS, PARENT_PROCESS };

struct ForkResult {
  ForkResultType type;
  pid_t pid;
};

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
      if (fork < 0) {
        // error
        ForkResult result = { FORK_FAILED, -1 };
        return result;
      } else if (fork == 0) {
        // child process
        int parent = vmem.current_process;
        vmem.current_process = i;
        vmem.metapage->process_info[i].pid = getpid();
        vmem.signal_fd = channel[0];
        unlock_metapage();
        send_signal(parent);
        ForkResult result = { CHILD_PROCESS, getpid() };
        return result;
      } else {
        // parent process
        close(channel[0]);
        wait_signal();
        // child has unlocked metapage, so we don't need to.
        ForkResult result = { PARENT_PROCESS, pid };
        return result;
      }
    }
    ForkResult result = { FORK_FAILED, -1 };
    return;
  }
  unlock_metapage();
}

class ReentrantLock {
private:
  int _owner;
  size_t _count;
  VRef<int> _lock;

public:
  ReentrantLock() : _owner(-1), _count(0), _lock(vnew<int>()) {
  }
  ~ReentrantLock() {
    _lock.free();
  }
  void lock() {
    if (_owner == internals::vmem.current_process) {
      _count++;
      return;
    }
    _lock.lock();
  }
  void unlock() {
    if (_owner == internals::vmem.current_process) {
      _count--;
      if (_count == 0) {
        _lock.unlock();
      }
    }
  }
};

class Semaphore {
private:
  int _owner;
  int _waiting[internals::MAX_PROCESS + 1];
  int _head, _tail;
  size_t _value;
  VRef<int> _lock;

public:
  Semaphore(size_t value) :
      _owner(0), _head(0), _tail(0), _value(value), _lock(vnew<int>()) {
  }
  void post() {
    int wakeup = -1;
    _lock.lock();
    if (_head == _tail) {
      _value++;
    } else {
      // don't increment value, as we'll pass that on to the next process.
      wakeup = _waiting[_head++];
      if (_head == internals::MAX_PROCESS + 1)
        _head = 0;
    }
    _lock.unlock();
    if (wakeup >= 0)
      internals::send_signal(wakeup);
  }
  void wait() {
    _lock.lock();
    if (_value > 0) {
      _value--;
      _lock.unlock();
      return;
    }
    _waiting[_tail++] = internals::vmem.current_process;
    if (_tail == internals::MAX_PROCESS + 1)
      _tail = 0;
    _lock.unlock();
    internals::wait_signal();
  }
};

template <typename T>
class Queue {
private:
  struct Node {
    VRef<Node> next;
    VRef<T> data;
  };
  Semaphore _sem;
  Vref<int> _lock;
  VRef<Node> head, tail;
  void remove() {
    VRef<Node> result = head;
    if (head == tail) {
      head = tail = vnull<Node>();
    }
    head = head->next;
  }
  void add(VRef<Node> node) {
    node->next = vnull<Node>();
    if (tail == NULL) {
      head = tail = node;
    } else {
      tail->next = node;
      tail = node;
    }
  }

public:
  void enqueue(VRef<T> item) {
    _lock.lock();
    VRef<Node> node = vnew<Node>();
    node->data = item;
    add(node);
    _lock.unlock();
    _sem.post();
  }
  VRef<T> dequeue() {
    _sem.wait();
    _lock.lock();
    VRef<Node> node = head;
    remove(head);
    VRef<T> result = node->data;
    node.free();
    _lock.unlock();
    return result;
  }
  template <typename T>
  void dequeue(VRef<T> &result) {
    _sem.wait();
    _lock.lock();
    VRef<Node> node = head;
    remove(head);
    result = node->data;
    node.free();
    _lock.unlock();
  }
};

}; // namespace vspace
