#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <new> // for placement new

#if __cplusplus >= 201100
#define HAVE_ATOMIC
#include <atomic>
#else
#error __cplusplus
#undef HAVE_ATOMIC
#endif

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

extern size_t config[4];

void init_flock_struct(
    struct flock &lock_info, size_t offset, size_t len, bool lock);
void lock_file(int fd, size_t offset, size_t len = 1);
void unlock_file(int fd, size_t offset, size_t len = 1);

void lock_metapage();
void unlock_metapage();
void init_metapage(bool create);

void send_signal(int processno);
void wait_signal();

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
    next = 0;
  }
};

struct VMem {
  static VMem vmem_global;
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
    if (result == MAP_FAILED)
      perror("mmap");
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
  void map_segments(int lastseg) {
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

static VMem &vmem = VMem::vmem_global;

static inline int find_level(size_t size) {
  int level = 0;
  while ((1 << (level + 8)) <= size)
    level += 8;
  while ((1 << level) < size)
    level++;
  return level;
}

static inline segaddr_t find_buddy(segaddr_t addr, int level) {
  return addr ^ (1 << level);
}

static inline bool is_free(VSeg seg, segaddr_t addr) {
  Block *block = seg.block_ptr(addr);
  return block->is_free();
}

void vmem_free(vaddr_t vaddr);
vaddr_t vmem_alloc(size_t size);

static inline vaddr_t allocated_ptr_to_vaddr(void *ptr) {
  char *addr = (char *) ptr - sizeof(Block);
  vaddr_t info = ((Block *) addr)->prev;
  int seg = info & (MAX_SEGMENTS - 1);
  unsigned char *segstart = vmem.segments[seg].base;
  size_t offset = (unsigned char *) ptr - segstart;
  return (seg << LOG2_SEGMENT_SIZE) | offset;
}

class Mutex {
private:
  int _owner;
  int _locklevel;
  vaddr_t _lock;

public:
  Mutex() : _owner(-1), _locklevel(0), _lock(vmem_alloc(1)) {
  }
  ~Mutex() {
    vmem_free(_lock);
  }
  void lock() {
    if (_owner == vmem.current_process) {
      _locklevel++;
    } else {
      lock_file(vmem.fd, METABLOCK_SIZE + _lock);
      _owner = vmem.current_process;
      _locklevel = 1;
    }
  }
  void unlock() {
    if (--_locklevel == 0) {
      assert(_owner == vmem.current_process);
      unlock_file(vmem.fd, METABLOCK_SIZE + _lock);
    }
  }
};

}; // namespace internals

template <typename T>
struct VRef {
private:
  internals::vaddr_t vaddr;

public:
  VRef() : vaddr(internals::VADDR_NULL) {
  }
  VRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }
  operator bool() {
    return vaddr != internals::VADDR_NULL;
  }
  bool is_null() {
    return vaddr == internals::VADDR_NULL;
  }
  VRef(void *ptr) {
    vaddr = internals::allocated_ptr_to_vaddr(ptr);
  }
  void *to_ptr() {
    return internals::vmem.to_ptr(vaddr);
  }
  T *as_ptr() {
    return (T *) to_ptr();
  }
  T &as_ref() {
    return *(T *) to_ptr();
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
    as_ptr()->~T(); // explicitly call destructor
    vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

template <typename T>
struct ZRef {
private:
  struct RefCount {
    std::atomic<ptrdiff_t> rc;
    T data;
    static internals::vaddr_t alloc() {
      return internals::vmem_alloc(sizeof(RefCount));
    }
  };
  internals::vaddr_t vaddr;
  std::atomic<ptrdiff_t> &refcount() {
    return ((RefCount *) (internals::vmem.to_ptr(vaddr)))->rc;
  }
  void retain() {
    refcount()++;
  }
  void release() {
    if (--refcount() == 0) {
      as_ref().~T();
      internals::vmem_free(vaddr);
    }
  }
  void *to_ptr() {
    return &((RefCount *) (internals::vmem.to_ptr(vaddr))->data);
  }

public:
  ZRef() : vaddr(internals::VADDR_NULL) {
  }
  ZRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }
  operator bool() {
    return vaddr != internals::VADDR_NULL;
  }
  bool is_null() {
    return vaddr == internals::VADDR_NULL;
  }
  ZRef(void *ptr) {
    vaddr = internals::allocated_ptr_to_vaddr(ptr);
  }
  T *as_ptr() {
    return (T *) to_ptr();
  }
  T &as_ref() {
    return *(T *) to_ptr();
  }
  T &operator*() {
    return *(T *) to_ptr();
  }
  T *operator->() {
    return (T *) to_ptr();
  }
  ZRef<T> &operator=(ZRef<T> other) {
    vaddr = other.vaddr;
  }
  template <typename U>
  ZRef<U> cast() {
    return ZRef<U>(vaddr);
  }
  void free() {
    as_ptr()->~T(); // explicitly call destructor
    vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

template <typename T>
VRef<T> vnull() {
  return VRef<T>(internals::VADDR_NULL);
}

template <typename T>
VRef<T> vnew() {
  VRef<T> result = VRef<T>(internals::vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T();
  return result;
}

template <typename T>
VRef<T> vnew_uninitialized() {
  VRef<T> result = VRef<T>(internals::vmem_alloc(sizeof(T)));
  return result;
}

template <typename T, typename Arg>
VRef<T> vnew(Arg arg) {
  VRef<T> result = VRef<T>(internals::vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg);
  return result;
}

template <typename T, typename Arg1, typename Arg2>
VRef<T> vnew(Arg1 arg1, Arg2 arg2) {
  VRef<T> result = VRef<T>(internals::vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg1, arg2);
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  VRef<T> result = VRef<T>(internals::vmem_alloc(sizeof(T)));
  new (result.to_ptr()) T(arg1, arg2, arg3);
  return result;
}

class VString {
private:
  internals::vaddr_t _buffer;
  size_t _len;

public:
  VString(const char *s) {
    _len = strlen(s);
    _buffer = internals::vmem_alloc(_len + 1);
    strcpy((char *) internals::vmem.to_ptr(_buffer), s);
  }
  VString(const char *s, size_t len) {
    _len = len;
    _buffer = internals::vmem_alloc(len + 1);
    strcpy((char *) internals::vmem.to_ptr(_buffer), s);
  }
  ~VString() {
    internals::vmem_free(_buffer);
  }
  size_t len() {
    return _len;
  }
  const char *str() {
    return (const char *) internals::vmem.to_ptr(_buffer);
  }
};

static inline VRef<VString> vstring(const char *s) {
  return vnew<VString>(s);
}

static inline VRef<VString> vstring(const char *s, size_t len) {
  return vnew<VString>(s, len);
}

enum ForkResultType { FORK_FAILED, CHILD_PROCESS, PARENT_PROCESS };

struct ForkResult {
  ForkResultType type;
  pid_t pid;
  ForkResult(ForkResultType type, pid_t pid) : type(type), pid(pid) {
  }
};

ForkResult fork_process();

typedef internals::Mutex Mutex;

class Semaphore {
private:
  int _owner;
  int _waiting[internals::MAX_PROCESS + 1];
  int _head, _tail;
  size_t _value;
  Mutex _lock;

public:
  Semaphore(size_t value) :
      _owner(0), _head(0), _tail(0), _value(value), _lock() {
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
  Mutex _lock;
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
