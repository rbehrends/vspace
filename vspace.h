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
#undef HAVE_ATOMIC
#endif

// vspace is a C++ library designed to allow processes in a
// multi-process environment to interoperate via mmapped shared memory.
// The library provides facilities for shared memory allocation and
// deallocation, shared mutexes, semaphores, queues, lists, and hash
// tables.
//
// The underlying file is organized starting with a block containing
// meta information such as free lists and process information necessary
// for IPC, followed by one or more segments of mmapped memory. Each
// address within the file is represented via its offset from the
// beginning of the first segment.
//
// These offsets are wrapped within the VRef<T> class, which works like
// a T* pointer, but transparently maps file offsets to memory
// locations.

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

typedef int ipc_signal_t;

bool send_signal(int processno, ipc_signal_t sig = 0);
ipc_signal_t check_signal(bool resume = false);
void accept_signals();
ipc_signal_t wait_signal();
void drop_pending_signals();

struct Block;
struct MetaPage;
struct ProcessChannel;

enum SignalState {
  Waiting = 0,
  Pending = 1,
  Accepted = 2,
};

struct ProcessInfo {
  pid_t pid;
  SignalState sigstate; // are there pending signals?
  ipc_signal_t signal;
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
  // the lowest bits of prev encode whether we are looking at an
  // allocated or free block. For an allocared block, the lowest bits
  // are 01. For a free block, they are 00 (for a null reference (==
  // -1), they are 11.
  //
  // For allocated blocks, the higher bits encode the segment and the
  // log2 of the block size (level). This requires LOG2_MAX_SEGMENTS +
  // log2(sizeof(vaddr_t) * 8) + 2 bits.
  //
  // For free blocks, the level is stored in the data field.
  vaddr_t prev;
  vaddr_t next;
  size_t data[1];
  bool is_free() {
    return (prev & 3) != 1;
  }
  int level() {
    if (is_free())
      return (int) data[0];
    else
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
  void mark_as_free(int level) {
    data[0] = level;
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
  inline size_t segment_no(vaddr_t vaddr) {
    return vaddr >> LOG2_SEGMENT_SIZE;
  }
  inline vaddr_t vaddr(size_t segno, segaddr_t addr) {
    return (segno << LOG2_SEGMENT_SIZE) | addr;
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
    if (vaddr == VADDR_NULL)
      return NULL;
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

inline Block *block_ptr(vaddr_t vaddr) {
  return vmem.block_ptr(vaddr);
}

#ifdef HAVE_ATOMIC_H
struct refcount_t {
  std::atomic<ptrdiff_t> rc;
  refcount_t(ptrdiff_t init) : rc(init) {
  }
  ptrdiff_t inc(vaddr_t vaddr) {
    rc++;
    return (ptrdiff_t) rc;
  }
  ptrdiff_t dec(vaddr_t vaddr) {
    rc--;
    return (ptrdiff_t) rc;
  }
}
#else
struct refcount_t {
  ptrdiff_t rc;
  static void lock(vaddr_t vaddr) {
    lock_file(vmem.fd, METABLOCK_SIZE + vaddr);
  }
  static void unlock(vaddr_t vaddr) {
    unlock_file(vmem.fd, METABLOCK_SIZE + vaddr);
  }
  refcount_t(ptrdiff_t init) : rc(init) {
  }
  ptrdiff_t inc(vaddr_t vaddr) {
    lock(vaddr);
    ptrdiff_t result = ++rc;
    unlock(vaddr);
    return result;
  }
  ptrdiff_t dec(vaddr_t vaddr) {
    lock(vaddr);
    ptrdiff_t result = --rc;
    unlock(vaddr);
    return result;
  }
};
#endif

static inline int
find_level(size_t size) {
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
      _owner = -1;
      unlock_file(vmem.fd, METABLOCK_SIZE + _lock);
    }
  }
};

}; // namespace internals

static inline void vmem_init() {
  internals::vmem.init();
}

static inline void vmem_deinit() {
}

template <typename T>
struct VRef {
private:
  internals::vaddr_t vaddr;

public:
  VRef() : vaddr(internals::VADDR_NULL) {
  }
  VRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }
  size_t offset() const {
    return vaddr;
  }
  operator bool() const {
    return vaddr != internals::VADDR_NULL;
  }
  bool is_null() {
    return vaddr == internals::VADDR_NULL;
  }
  VRef(void *ptr) {
    vaddr = internals::allocated_ptr_to_vaddr(ptr);
  }
  void *to_ptr() const {
    return internals::vmem.to_ptr(vaddr);
  }
  T *as_ptr() const {
    return (T *) to_ptr();
  }
  T &as_ref() const {
    return *(T *) to_ptr();
  }
  T &operator*() const {
    return *(T *) to_ptr();
  }
  T *operator->() {
    return (T *) to_ptr();
  }
  VRef<T> &operator=(VRef<T> other) {
    vaddr = other.vaddr;
    return *this;
  }
  T &operator[](size_t index) {
    return as_ptr()[index];
  }
  template <typename U>
  VRef<U> cast() {
    return VRef<U>(vaddr);
  }
  static VRef<T> alloc(size_t n = 1) {
    return VRef<T>(internals::vmem_alloc(n * sizeof(T)));
  }
  void free() {
    as_ptr()->~T(); // explicitly call destructor
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

template <typename T>
VRef<T> vnull() {
  return VRef<T>(internals::VADDR_NULL);
}

template <typename T>
VRef<T> vnew() {
  VRef<T> result = VRef<T>::alloc();
  new (result.to_ptr()) T();
  return result;
}

template <typename T>
VRef<T> vnew_uninitialized() {
  VRef<T> result = VRef<T>::alloc();
  return result;
}

template <typename T>
VRef<T> vnew_array(size_t n) {
  VRef<T> result = VRef<T>::alloc(n);
  T *ptr = result.as_ptr();
  for (size_t i = 0; i < n; i++) {
    new (ptr + i) T();
  }
  return result;
}

template <typename T>
VRef<T> vnew_uninitialized_array(size_t n) {
  VRef<T> result = VRef<T>::alloc(n);
  return result;
}

template <typename T, typename Arg>
VRef<T> vnew(Arg arg) {
  VRef<T> result = VRef<T>::alloc();
  new (result.to_ptr()) T(arg);
  return result;
}

template <typename T, typename Arg1, typename Arg2>
VRef<T> vnew(Arg1 arg1, Arg2 arg2) {
  VRef<T> result = VRef<T>::alloc();
  new (result.to_ptr()) T(arg1, arg2);
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  VRef<T> result = VRef<T>::alloc();
  new (result.to_ptr()) T(arg1, arg2, arg3);
  return result;
}

template <typename T>
struct ZRef {
private:
  struct RefCounted {
    internals::refcount_t rc;
#if __cplusplus >= 201100
    alignas(T)
#endif
        char data[sizeof(T)];
    RefCounted() : rc(1) {
    }
  };
  internals::vaddr_t vaddr;
  internals::refcount_t &refcount() {
    return ((RefCounted *) (internals::vmem.to_ptr(vaddr)))->rc;
  }
  void *to_ptr() {
    return &(((RefCounted *) (internals::vmem.to_ptr(vaddr)))->data);
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
  T *as_ptr() const {
    return (T *) to_ptr();
  }
  T &as_ref() const {
    return *(T *) to_ptr();
  }
  T &operator*() const {
    return *(T *) to_ptr();
  }
  T *operator->() {
    return (T *) to_ptr();
  }
  ZRef<T> &operator=(ZRef<T> other) {
    vaddr = other.vaddr;
  }
  template <typename U>
  ZRef<U> cast() const {
    return ZRef<U>(vaddr);
  }
  void retain() {
    refcount().inc(vaddr);
  }
  void release() {
    if (refcount().dec(vaddr) == 0) {
      as_ref().~T();
      internals::vmem_free(vaddr);
    }
  }
  void free() {
    as_ptr()->~T(); // explicitly call destructor
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
  static internals::vaddr_t alloc() {
    return internals::vmem_alloc(sizeof(RefCounted));
  }
};

template <typename T>
ZRef<T> znull() {
  return ZRef<T>(internals::VADDR_NULL);
}

template <typename T>
ZRef<T> znew() {
  ZRef<T> result = ZRef<T>::alloc();
  new (result.to_ptr()) T();
  return result;
}

template <typename T>
ZRef<T> znew_uninitialized() {
  ZRef<T> result = ZRef<T>::alloc();
  return result;
}

template <typename T>
ZRef<T> znew_array(size_t n) {
  ZRef<T> result = ZRef<T>::alloc();
  T *ptr = result.as_ptr();
  for (size_t i = 0; i < n; i++) {
    new (ptr + i) T();
  }
  return result;
}

template <typename T>
ZRef<T> znew_uninitialized_array(size_t n) {
  ZRef<T> result = ZRef<T>::alloc();
  return result;
}

template <typename T, typename Arg>
ZRef<T> znew(Arg arg) {
  ZRef<T> result = ZRef<T>::alloc();
  new (result.to_ptr()) T(arg);
  return result;
}

template <typename T, typename Arg1, typename Arg2>
ZRef<T> znew(Arg1 arg1, Arg2 arg2) {
  ZRef<T> result = ZRef<T>::alloc();
  new (result.to_ptr()) T(arg1, arg2);
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
ZRef<T> znew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  ZRef<T> result = ZRef<T>::alloc();
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
    _buffer = vnew_uninitialized_array<char>(_len + 1);
    strcpy(_buffer.as_ptr(), s);
  }
  VString(const char *s, size_t len) {
    _len = len;
    _buffer = vnew_uninitialized_array<char>(len + 1);
    char *buffer = _buffer.as_ptr();
    memcpy(buffer, s, len);
    buffer[len] = '\0';
  }
  ~VString() {
    _buffer.free();
  }
  size_t len() const {
    return _len;
  }
  VRef<VString> clone() const {
    return vnew<VString>(_buffer.as_ptr(), _len);
  }
  const char *str() const {
    return _buffer.as_ptr();
  }
};

static inline VRef<VString> vstring(const char *s) {
  return vnew<VString>(s);
}

static inline VRef<VString> vstring(const char *s, size_t len) {
  return vnew<VString>(s, len);
}

template <typename Spec>
class VMap {
private:
  typedef typename Spec::Key K;
  typedef typename Spec::Value V;
  struct Node {
    VRef<Node> next;
    size_t hash;
    VRef<K> key;
    VRef<V> value;
  };
  VRef<VRef<Node> > _buckets;
  size_t _nbuckets;

  void _lock_bucket(size_t b) {
    internals::lock_file(internals::vmem.fd,
        internals::METABLOCK_SIZE + _buckets.offset()
            + sizeof(VRef<Node>) * b);
  }
  void _unlock_bucket(size_t b) {
    internals::unlock_file(internals::vmem.fd,
        internals::METABLOCK_SIZE + _buckets.offset()
            + sizeof(VRef<Node>) * b);
  }

public:
  VMap(size_t size = 1024);
  ~VMap();
  bool add(VRef<K> key, VRef<V> value, VRef<K> &oldkey, VRef<V> &oldvalue,
      bool replace = true);
  bool add(VRef<K> key, VRef<V> value, bool replace = true) {
    VRef<K> oldkey;
    VRef<V> oldvalue;
    return add(key, value, oldkey, oldvalue, replace);
  }
  bool remove(VRef<K> key, VRef<K> &oldkey, VRef<V> &oldvalue);
  bool remove(VRef<K> key) {
    VRef<K> oldkey;
    VRef<V> oldvalue;
    return remove(key, oldkey, oldvalue);
  }
  bool find(VRef<K> key, VRef<V> &value);
  VRef<V> find(VRef<K> key) {
    VRef<V> value;
    if (find(key, value))
      return value;
    else
      return vnull<V>();
  }
};

template <typename Spec>
VMap<Spec>::VMap(size_t size) {
  _nbuckets = 8;
  while (_nbuckets < size)
    _nbuckets *= 2;
  _buckets = vnew_array<VRef<Node> >(_nbuckets);
}

template <typename Spec>
VMap<Spec>::~VMap() {
  for (size_t b = 0; b < _nbuckets; b++) {
    _lock_bucket(b);
    VRef<Node> node = _buckets[b];
    while (node) {
      Node *node_ptr = node.as_ptr();
      VRef<Node> next = node_ptr->next;
      Spec::free_key(node_ptr->key);
      Spec::free_value(node_ptr->value);
      node.free();
      node = next;
    }
    _unlock_bucket(b);
  }
}

template <typename Spec>
bool VMap<Spec>::add(VRef<K> key, VRef<V> value, VRef<K> &oldkey,
    VRef<V> &oldvalue, bool replace) {
  size_t hash = Spec::hash(key.as_ptr());
  size_t b = hash & (_nbuckets - 1);
  _lock_bucket(b);
  VRef<Node> node = _buckets[b];
  VRef<Node> last = vnull<Node>();
  while (!node.is_null()) {
    Node *node_ptr = node.as_ptr();
    if (hash == node_ptr->hash
        && Spec::equal(key.as_ptr(), node_ptr->key.as_ptr())) {
      value = node_ptr->value;
      if (!last.is_null()) {
        // move to front
        last->next = node_ptr->next;
        node_ptr->next = _buckets[b];
        _buckets[b] = node;
      }
      oldkey = node_ptr->key;
      oldvalue = node_ptr->value;
      if (replace)
        node_ptr->value = value;
      _unlock_bucket(b);
      return false;
    }
    last = node;
    node = node->next;
  }
  node = vnew<Node>();
  Node *node_ptr = node.as_ptr();
  node_ptr->hash = hash;
  node_ptr->key = key;
  node_ptr->value = value;
  node_ptr->next = _buckets[b];
  _buckets[b] = node;
  oldkey = key;
  oldvalue = value;
  _unlock_bucket(b);
  return true;
}

template <typename Spec>
bool VMap<Spec>::remove(VRef<K> key, VRef<K> &oldkey, VRef<V> &oldvalue) {
  size_t hash = Spec::hash(key.as_ptr());
  size_t b = hash & (_nbuckets - 1);
  _lock_bucket(b);
  VRef<Node> node = _buckets[b];
  VRef<Node> last = vnull<Node>();
  while (!node.is_null()) {
    Node *node_ptr = node.as_ptr();
    if (hash == node_ptr->hash
        && Spec::equal(key.as_ptr(), node_ptr->key.as_ptr())) {
      oldkey = node_ptr->key;
      oldvalue = node_ptr->value;
      // remove from list
      if (last.is_null()) {
        _buckets[b] = node_ptr->next;
      } else {
        last->next = node_ptr->next;
      }
      _unlock_bucket(b);
      return true;
    }
    last = node;
    node = node->next;
  }
  _unlock_bucket(b);
  return false;
}

template <typename Spec>
bool VMap<Spec>::find(VRef<K> key, VRef<V> &value) {
  size_t hash = Spec::hash(key.as_ptr());
  size_t b = hash & (_nbuckets - 1);
  _lock_bucket(b);
  VRef<Node> node = _buckets[b];
  VRef<Node> last = vnull<Node>();
  while (!node.is_null()) {
    Node *node_ptr = node.as_ptr();
    if (hash == node_ptr->hash
        && Spec::equal(key.as_ptr(), node_ptr->key.as_ptr())) {
      value = node_ptr->value;
      // move to front
      if (!last.is_null()) {
        last->next = node_ptr->next;
        node_ptr->next = _buckets[b];
      }
      _buckets[b] = node;
      _unlock_bucket(b);
      return true;
    }
    last = node;
    node = node->next;
  }
  _unlock_bucket(b);
  return false;
}

struct DictSpec {
  typedef VString Key;
  typedef VString Value;
  static size_t hash(const VString *s) {
    // DJB hash
    size_t len = s->len();
    const char *str = s->str();
    size_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
      hash = 33 * hash + str[i];
    }
    return hash;
  }
  static bool equal(const VString *s1, const VString *s2) {
    if (s1->len() != s2->len())
      return false;
    size_t len = s1->len();
    const char *str1 = s1->str(), *str2 = s2->str();
    for (size_t i = 0; i < len; i++) {
      if (str1[i] != str2[i])
        return false;
    }
    return true;
  }
  // By default, we do not make assumptions about ownership. It is
  // up to the caller to free keys and values if needed or to
  // define appropriate `free_key()` and `free_value()` functions
  // that work. Note in particular that keys and values may occur
  // more than once in a map and if that happens, they must not
  // be freed multiple times.
  static void free_key(VRef<Key> key) {
    // do nothing
  }
  static void free_value(VRef<Value> value) {
    // do nothing
  }
};

typedef VMap<DictSpec> VDict;

pid_t fork_process();

typedef internals::Mutex Mutex;

class Semaphore {
private:
  int _owner;
  int _waiting[internals::MAX_PROCESS + 1];
  internals::ipc_signal_t _signals[internals::MAX_PROCESS + 1];
  int _head, _tail;
  void next(int &index) {
    if (index == internals::MAX_PROCESS)
      index = 0;
    else
      index++;
  }
  size_t _value;
  Mutex _lock;

public:
  Semaphore(size_t value = 0) :
      _owner(0), _head(0), _tail(0), _value(value), _lock() {
  }
  size_t value() {
    return _value;
  }
  void post();
  bool try_wait();
  void wait();
  bool start_wait(internals::ipc_signal_t sig = 0);
  void stop_wait();
};

template <typename T>
class Queue {
private:
  struct Node {
    VRef<Node> next;
    VRef<T> data;
  };
  Semaphore _incoming;
  Semaphore _outgoing;
  bool _bounded;
  Mutex _lock;
  VRef<Node> _head, _tail;
  void remove() {
    VRef<Node> result = _head;
    if (_head->next.is_null()) {
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
  template <typename U>
  friend class SendQueue;
  template <typename U>
  friend class ReceiveQueue;

  void enqueue_nowait(VRef<T> item) {
    _lock.lock();
    VRef<Node> node = vnew<Node>();
    node->data = item;
    add(node);
    _lock.unlock();
    _incoming.post();
  }
  VRef<T> dequeue_nowait() {
    _lock.lock();
    VRef<Node> node = _head;
    remove();
    VRef<T> result = node->data;
    node.free();
    _lock.unlock();
    if (_bounded)
      _outgoing.post();
    return result;
  }

public:
  Queue(size_t bound = 0) :
      _incoming(0),
      _outgoing(bound),
      _bounded(bound != 0),
      _head(),
      _tail(),
      _lock() {
  }
  void enqueue(VRef<T> item) {
    if (_bounded)
      _outgoing.wait();
    enqueue_nowait(item);
  }
  VRef<T> dequeue() {
    _incoming.wait();
    return dequeue_nowait();
  }
  VRef<T> try_dequeue() {
    if (_incoming.try_wait())
      return dequeue_nowait();
    else
      return vnull<T>();
  }
};

class Event {
public:
  virtual bool start_listen(internals::ipc_signal_t sig) = 0;
  virtual void stop_listen() = 0;
};

class EventSet {
private:
  Event *_default_events[4];
  Event **_events;
  size_t _count;
  size_t _cap;

public:
  EventSet() : _count(0), _cap(4), _events(_default_events) {
  }
  ~EventSet() {
    if (_events != _default_events)
      delete _events;
  }
  void add(Event *event);
  void add(Event &event) {
    add(&event);
  }
  EventSet &operator<<(Event *event) {
    add(event);
    return *this;
  }
  EventSet &operator<<(Event &event) {
    add(event);
    return *this;
  }
  int wait();
};

class WaitSemaphore : public Event {
private:
  VRef<Semaphore> _sem;

public:
  WaitSemaphore(VRef<Semaphore> sem) : _sem(sem) {
  }
  virtual bool start_listen(internals::ipc_signal_t sig) {
    return _sem->start_wait(sig);
  }
  virtual void stop_listen() {
    _sem->stop_wait();
  }
  void complete() {
  }
};

template <typename T>
class SendQueue : public Event {
private:
  VRef<Queue<T> > _queue;

public:
  SendQueue(VRef<Queue<T> > queue) : _queue(queue) {
  }
  virtual bool start_listen(internals::ipc_signal_t sig) {
    return _queue->_outgoing.start_wait(sig);
  }
  virtual void stop_listen() {
    _queue->_outgoing.stop_wait();
  }
  void complete(VRef<T> item) {
    _queue->enqueue_nowait(item);
  }
};

template <typename T>
class ReceiveQueue : public Event {
private:
  VRef<Queue<T> > _queue;

public:
  ReceiveQueue(VRef<Queue<T> > queue) : _queue(queue) {
  }
  virtual bool start_listen(internals::ipc_signal_t sig) {
    return _queue->_incoming.start_wait(sig);
  }
  virtual void stop_listen() {
    _queue->_incoming.stop_wait();
  }
  VRef<T> complete() {
    return _queue->dequeue_nowait();
  }
};

}; // namespace vspace
