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
struct ProcessChannel;

struct ProcessInfo {
  pid_t pid;
  char fifo_path[256 - sizeof(pid_t)];
};

struct MetaPage {
  size_t config_header[4];
  vaddr_t freelist[LOG2_SEGMENT_SIZE + 1];
  int segment_count;
  ProcessInfo process_info[MAX_PROCESS];
};

// We use pipes/fifos to signal processes. For each process, fd_read is
// where the process reads from and fd_write is where other processes
// signal the reading process. Only single bytes are sent across each
// channel. Because the effect of concurrent writes is undefined, bytes
// must only be written by a single process at the time. This is usually
// the case when the sending process knows that the receiving process is
// waiting for a resource that the sending process currently holds. See
// the Semaphore implementation for an example.

struct ProcessChannel {
  int fd_read, fd_write;
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
    return (prev & 3) != 1;
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

struct VSeg {
  unsigned char *base;
  inline Block *block_ptr(segaddr_t addr) {
    return (Block *) (base + addr);
  }
  bool is_free(segaddr_t addr) {
    Block *block = block_ptr(addr);
    return block->is_free();
  }
  inline void *ptr(segaddr_t addr) {
    return (void *) (base + addr);
  }
  VSeg() : base(NULL) {
  }
  VSeg(void *base) : base((unsigned char *) base) {
  }
};

struct VMem {
  static VMem vmem_global;
  MetaPage *metapage;
  int fd;
  int current_process; // index into process table
  vaddr_t *freelist; // reference to metapage information
  VSeg segments[MAX_SEGMENTS];
  ProcessChannel channels[MAX_PROCESS];
  inline VSeg segment(vaddr_t vaddr) {
    return segments[vaddr >> LOG2_SEGMENT_SIZE];
  }
  inline segaddr_t segaddr(vaddr_t vaddr) {
    if (vaddr == VADDR_NULL)
      return SEGADDR_NULL;
    return vaddr & SEGMENT_MASK;
  }
  inline Block *block_ptr(vaddr_t vaddr) {
    if (vaddr == VADDR_NULL)
      return NULL;
    return (Block *) (segment(vaddr).base + segaddr(vaddr));
  }
  inline void ensure_is_mapped(vaddr_t vaddr) {
    int seg = vaddr >> LOG2_SEGMENT_SIZE;
    if (segments[seg].base != NULL)
      return;
    segments[seg] = mmap_segment(seg);
  }
  inline void *to_ptr(vaddr_t vaddr) {
    ensure_is_mapped(vaddr);
    return segment(vaddr).ptr(segaddr(vaddr));
  }
  size_t filesize();
  void init(int fd);
  void init();
  bool init(const char *path);
  void *mmap_segment(int seg);
  void add_segment();
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
    return *this;
  }
  T& operator[](size_t index) {
    return as_ptr()[index];
  }
  template <typename U>
  VRef<U> cast() {
    return VRef<U>(vaddr);
  }
  void free() {
    as_ptr()->~T(); // explicitly call destructor
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

#if 0
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
    return &(((RefCount *) (internals::vmem.to_ptr(vaddr)))->data);
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
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};
#endif

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

template <typename T>
VRef<T> vnew_array(size_t n) {
  VRef<T> result = VRef<T>(internals::vmem_alloc(n * sizeof(T)));
  T *ptr = result.as_ptr();
  for (size_t i = 0; i < n; i++) {
    new(ptr+i) T();
  }
  return result;
}

template <typename T>
VRef<T> vnew_uninitialized_array(size_t n) {
  VRef<T> result = VRef<T>(internals::vmem_alloc(n * sizeof(T)));
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
  VRef<char> _buffer;
  size_t _len;

public:
  VString(const char *s) {
    _len = strlen(s);
    _buffer = vnew_uninitialized_array<char>(_len+1);
    strcpy(_buffer.as_ptr(), s);
  }
  VString(const char *s, size_t len) {
    _len = len;
    _buffer = vnew_uninitialized_array<char>(len+1);
    char *buffer = _buffer.as_ptr();
    memcpy(buffer, s, len);
    buffer[len] = '\0';
  }
  ~VString() {
    internals::vmem_free(_buffer);
  }
  size_t len() {
    return _len;
  }
  const char *str() {
    return _buffer.as_ptr();
  }
};

static inline VRef<VString> vstring(const char *s) {
  return vnew<VString>(s);
}

static inline VRef<VString> vstring(const char *s, size_t len) {
  return vnew<VString>(s, len);
}

pid_t fork_process();

typedef internals::Mutex Mutex;

class Semaphore {
private:
  int _owner;
  int _waiting[internals::MAX_PROCESS + 1];
  int _head, _tail;
  size_t _value;
  Mutex _lock;

public:
  Semaphore(size_t value = 0) :
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
  VRef<Node> _head, _tail;
  void remove() {
    VRef<Node> result = _head;
    if (_head == _tail) {
      _head = _tail = vnull<Node>();
    } else {
      _head = _head->next;
    }
  }
  void add(VRef<Node> node) {
    node->next = vnull<Node>();
    if (_tail.is_null()) {
      _head = _tail = node;
    } else {
      _tail->next = node;
      _tail = node;
    }
  }

public:
  Queue() : _sem(0) {}
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
    VRef<Node> node = _head;
    remove();
    VRef<T> result = node->data;
    node.free();
    _lock.unlock();
    return result;
  }
  void dequeue(VRef<T> &result) {
    _sem.wait();
    _lock.lock();
    VRef<Node> node = _head;
    remove(_head);
    result = node->data;
    node.free();
    _lock.unlock();
  }
};

}; // namespace vspace
