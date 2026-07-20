#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <assert.h>
#include <new> // for placement new
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

#if __cplusplus >= 201103L
#include <atomic>
#endif




// VSpace is a C++ library designed to allow processes in a
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

enum ErrCode {
  ErrNone,
  ErrGeneral,
  ErrFile,
  ErrMMap,
  ErrOS,
};

template <typename T>
struct Result {
  bool ok;
  T result;
  Result(T result) : ok(true), result(result) {
  }
  Result() : ok(false), result(default_value()) {
  }
private:
  T& default_value() {
    static T result;
    return result;
  }
};

typedef void (*AllocationFailureHandler)(size_t size);

void set_allocation_failure_handler(AllocationFailureHandler handler);

struct Status {
  ErrCode err;
  bool ok() {
    return err == ErrNone;
  }
  operator bool() {
    return err == ErrNone;
  }
  Status(ErrCode err) : err(err) {
  }
};

namespace internals {

template <typename T>
struct AlignmentOf {
  struct Helper {
    char prefix;
    T object;
  };
  enum { value = sizeof(Helper) - sizeof(T) };
};

#if __cplusplus >= 201103L
#define VSPACE_ALIGNOF(T) alignof(T)
#else
#define VSPACE_ALIGNOF(T) AlignmentOf<T>::value
#endif

typedef size_t segaddr_t;

typedef size_t vaddr_t;

const segaddr_t SEGADDR_NULL = ~(segaddr_t) 0;
const vaddr_t VADDR_NULL = ~(segaddr_t) 0;

static const int MAX_PROCESS = 64;
static const size_t METABLOCK_SIZE = 128 * 1024; // 128 KB
static const unsigned REFCOUNT_LOCK_BITS = 8;
static const size_t REFCOUNT_NUM_LOCKS = 1 << REFCOUNT_LOCK_BITS;
static const int LOG2_SEGMENT_SIZE = 28; // 256 MB
static const int LOG2_MAX_SEGMENTS = 10; // 256 GB
static const size_t MAX_SEGMENTS = size_t(1) << LOG2_MAX_SEGMENTS;
static const size_t SEGMENT_SIZE = size_t(1) << LOG2_SEGMENT_SIZE;
static const size_t SEGMENT_MASK = (SEGMENT_SIZE - 1);

void pthread_fatal(const char *operation, int error);

class SharedMutex {
private:
  pthread_mutex_t _mutex;
  SharedMutex(const SharedMutex &);
  SharedMutex &operator=(const SharedMutex &);
public:
  explicit SharedMutex(bool recursive = false);
  ~SharedMutex();
  void lock();
  void unlock();
  pthread_mutex_t *native_handle() { return &_mutex; }
};

class SharedCondition {
private:
  pthread_cond_t _condition;
  SharedCondition(const SharedCondition &);
  SharedCondition &operator=(const SharedCondition &);
public:
  SharedCondition();
  ~SharedCondition();
  void wait(SharedMutex &mutex);
  void signal();
  void broadcast();
};



bool lock_metapage();
void unlock_metapage();
void hash_lock(vaddr_t vaddr);
void hash_unlock(vaddr_t vaddr);
Status init_metapage(bool create);

struct Block;
struct MetaPage;

enum SharedMemState {
  SharedMemUninitialized = 0,
  SharedMemInitializing = 1,
  SharedMemInitialized = 2,
};

struct FileHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t init_state;
  uint32_t header_size;
  uint32_t metablock_size;
  uint32_t max_process;
  uint32_t segment_size;
  uint32_t max_segments;
  uint32_t size_t_size;
  uint32_t pointer_size;
  uint32_t pthread_mutex_size;
  uint32_t pthread_mutex_align;
  uint32_t pthread_cond_size;
  uint32_t pthread_cond_align;
  uint32_t layout_id;
};

enum ProcessState {
  ProcessUnused = 0,
  ProcessStarting = 1,
  ProcessRunning = 2,
};

enum WaitState {
  WaitIdle = 0,
  WaitActive = 1,
  WaitSelected = 2,
};

// An EventId instance identifies one candidate event in a wait selection.
//
// The `process_slot` and `process_incarnation` attributes identify the
// waiting process instance. The `wait_sequence_id` attribute identifies a
// particular wait selection by that process. The `event_index` attribute
// identifies the candidate event within that selection.
//
// Copies may be registered with multiple event sources. try_select() allows
// exactly one candidate to satisfy an active selection and rejects stale or
// losing candidates.
struct EventId {
  int process_slot;
  size_t process_incarnation;
  size_t wait_sequence_id;
  int event_index;
};

inline bool operator==(const EventId &left, const EventId &right) {
  return left.process_slot == right.process_slot
      && left.process_incarnation == right.process_incarnation
      && left.wait_sequence_id == right.wait_sequence_id
      && left.event_index == right.event_index;
}

struct WaitContext {
  SharedMutex notify_mutex;
  SharedCondition notify_condition;
  WaitState state;
  size_t sequence_id;
  int selected_event;
  WaitContext() : state(WaitIdle), sequence_id(0), selected_event(-1) { }
};

struct ProcessInfo {
  pid_t pid;
  ProcessState slot_state;
  size_t process_incarnation;
  bool startup_acknowledged;
  WaitContext wait_context;
  ProcessInfo() : pid(0), slot_state(ProcessUnused), process_incarnation(0),
      startup_acknowledged(false), wait_context() { }
};

struct MetaPage {
  FileHeader header;
  SharedMutex allocator_lock;
  SharedMutex process_table_mutex;
  SharedCondition process_startup_condition;
#if __cplusplus < 201103L
  SharedMutex refcount_locks[REFCOUNT_NUM_LOCKS];
#endif
  vaddr_t freelist[LOG2_SEGMENT_SIZE + 1];
  int segment_count;
  ProcessInfo process_info[MAX_PROCESS];
};

enum EventSelection {
  EventQueued,
  EventAlreadyQueued,
  EventSelected,
  EventAlreadySelected,
};

// cooperative waiting mechanism
EventId join_selection(int event_index = 0);
bool try_select(const EventId &id);
int await_selection(const EventId &id);
void leave_selection(const EventId &id);

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
  // For free blocks, the level is stored in the data field, and prev and
  // next link the block into its free list.
  //
  // For allocated blocks, next stores the number of bytes occupied by
  // constructed objects. A value of zero denotes raw storage whose
  // destruction is the caller's responsibility. The vnew helpers set this
  // value after construction; vmem_alloc and VRef::alloc leave it at zero.
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
  size_t constructed_size() {
    assert(!is_free());
    return next;
  }
  void mark_as_constructed(size_t size) {
    assert(!is_free());
    next = size;
  }
};

#if __cplusplus >= 201103L
static_assert(offsetof(Block, data) % VSPACE_ALIGNOF(pthread_mutex_t) == 0,
    "VSpace allocations must align pthread mutexes");
static_assert(offsetof(Block, data) % VSPACE_ALIGNOF(pthread_cond_t) == 0,
    "VSpace allocations must align pthread conditions");
static_assert(sizeof(MetaPage) <= METABLOCK_SIZE,
    "MetaPage must fit in the fixed metapage allocation");
#else
typedef char MetaPageMustFitInMetablock[
    sizeof(MetaPage) <= METABLOCK_SIZE ? 1 : -1];
#endif

template <typename T>
inline void check_allocation_alignment() {
#if __cplusplus >= 201103L
  static_assert(offsetof(Block, data) % VSPACE_ALIGNOF(T) == 0,
      "VSpace does not support this type's alignment");
#else
  typedef char VSpaceDoesNotSupportThisTypeAlignment[
      offsetof(Block, data) % AlignmentOf<T>::value == 0 ? 1 : -1];
  (void) sizeof(VSpaceDoesNotSupportThisTypeAlignment);
#endif
}

struct VSeg {
  unsigned char *base;
  inline bool is_free() {
    return base == NULL;
  }
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
  std::FILE *file_handle;
  int current_process; // index into process table
  vaddr_t *freelist; // reference to metapage information
  VSeg segments[MAX_SEGMENTS];
  VMem() : metapage(NULL), fd(-1), file_handle(NULL), current_process(-1),
      freelist(NULL) { }
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
    if (segments[seg].is_free())
      segments[seg] = mmap_segment(seg);
  }
  inline void *to_ptr(vaddr_t vaddr) {
    if (vaddr == VADDR_NULL)
      return NULL;
    ensure_is_mapped(vaddr);
    return segment(vaddr).ptr(segaddr(vaddr));
  }
  size_t filesize();
  Status init(int fd);
  Status init();
  Status init(const char *path);
  void deinit();
  void *mmap_segment(int seg);
  void add_segment();
};

static VMem &vmem = VMem::vmem_global;

inline Block *block_ptr(vaddr_t vaddr) {
  return vmem.block_ptr(vaddr);
}

#if __cplusplus >= 201103L
#if __cplusplus >= 201703L
static_assert(std::atomic<ptrdiff_t>::is_always_lock_free,
    "VSpace requires lock-free std::atomic<ptrdiff_t>");
#endif
struct refcount_t {
  std::atomic<ptrdiff_t> rc;
  refcount_t(ptrdiff_t init) : rc(init) { }
  ptrdiff_t inc(vaddr_t) { return ++rc; }
  ptrdiff_t dec(vaddr_t) { return --rc; }
};
#else
struct refcount_t {
  ptrdiff_t rc;
  refcount_t(ptrdiff_t init) : rc(init) { }
  ptrdiff_t inc(vaddr_t vaddr) {
    hash_lock(vaddr);
    ptrdiff_t result = ++rc;
    hash_unlock(vaddr);
    return result;
  }
  ptrdiff_t dec(vaddr_t vaddr) {
    hash_lock(vaddr);
    ptrdiff_t result = --rc;
    hash_unlock(vaddr);
    return result;
  }
};
#endif

static inline int find_level(size_t size) {
  int level = 0;
  while ((size_t(1) << (level + 8)) <= size)
    level += 8;
  while ((size_t(1) << level) < size)
    level++;
  return level;
}

static inline segaddr_t find_buddy(segaddr_t addr, int level) {
  return addr ^ (size_t(1) << level);
}

void vmem_free(vaddr_t vaddr);
vaddr_t vmem_alloc(size_t size);
char *validate_allocator();

static inline Block *allocated_block(vaddr_t vaddr) {
  return vmem.block_ptr(vaddr - offsetof(Block, data));
}

static inline size_t constructed_size(vaddr_t vaddr) {
  return allocated_block(vaddr)->constructed_size();
}

static inline void mark_as_constructed(vaddr_t vaddr, size_t size) {
  allocated_block(vaddr)->mark_as_constructed(size);
}

static inline vaddr_t allocated_ptr_to_vaddr(void *ptr) {
  char *addr = (char *) ptr - offsetof(Block, data);
  vaddr_t info = ((Block *) addr)->prev;
  size_t seg = (info >> 2) & (MAX_SEGMENTS - 1);
  unsigned char *segstart = vmem.segments[seg].base;
  size_t offset = (unsigned char *) ptr - segstart;
  return (seg << LOG2_SEGMENT_SIZE) | offset;
}

}; // namespace internals

static inline Status vmem_init() {
  return internals::vmem.init();
}

static inline void vmem_deinit() {
  internals::vmem.deinit();
}

template <typename T>
struct VRef {
private:
  internals::vaddr_t vaddr;
  VRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }
public:
  VRef() : vaddr(internals::VADDR_NULL) {
  }
  static VRef<T> from_vaddr(internals::vaddr_t vaddr) {
    return VRef(vaddr);
  }
  size_t offset() const {
    return vaddr;
  }
  bool operator==(VRef<T> other) {
    return vaddr == other.vaddr;
  }
  bool operator!=(VRef<T> other) {
    return vaddr != other.vaddr;
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
    return VRef<U>::from_vaddr(vaddr);
  }
  static VRef<T> alloc(size_t n = 1) {
    internals::check_allocation_alignment<T>();
    return VRef<T>(internals::vmem_alloc(n * sizeof(T)));
  }
  void free() {
    T *ptr = as_ptr();
    size_t count = internals::constructed_size(vaddr) / sizeof(T);
    while (count > 0)
      ptr[--count].~T();
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

template <>
struct VRef<void> {
private:
  internals::vaddr_t vaddr;
  VRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }

public:
  VRef() : vaddr(internals::VADDR_NULL) {
  }
  static VRef<void> from_vaddr(internals::vaddr_t vaddr) {
    return VRef(vaddr);
  }
  size_t offset() const {
    return vaddr;
  }
  operator bool() const {
    return vaddr != internals::VADDR_NULL;
  }
  bool operator==(VRef<void> other) {
    return vaddr == other.vaddr;
  }
  bool operator!=(VRef<void> other) {
    return vaddr != other.vaddr;
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
  void *as_ptr() const {
    return (void *) to_ptr();
  }
  VRef<void> &operator=(VRef<void> other) {
    vaddr = other.vaddr;
    return *this;
  }
  template <typename U>
  VRef<U> cast() {
    return VRef<U>::from_vaddr(vaddr);
  }
  static VRef<void> alloc(size_t n = 1) {
    return VRef<void>(internals::vmem_alloc(n));
  }
  void free() {
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }
};

namespace internals {

template <typename T, typename Ref>
class VMemConstructionGuard {
private:
  Ref _ref;
  T *_ptr;
  size_t _num_constructed;
  bool _cleanup_required;
  VMemConstructionGuard(const VMemConstructionGuard &);
  VMemConstructionGuard &operator=(const VMemConstructionGuard &);

public:
  VMemConstructionGuard(Ref ref, T *ptr)
      : _ref(ref), _ptr(ptr), _num_constructed(0), _cleanup_required(true) { }
  ~VMemConstructionGuard() {
    if (!_cleanup_required)
      return;
    while (_num_constructed > 0)
      _ptr[--_num_constructed].~T();
    _ref.free();
  }
  void element_constructed() {
    _num_constructed++;
  }
  void commit() {
    _cleanup_required = false;
  }
};

} // namespace internals

template <typename T>
VRef<T> vnull() {
  return VRef<T>::from_vaddr(internals::VADDR_NULL);
}

template <typename T>
VRef<T> vnew() {
  VRef<T> result = VRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T();
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
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
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  for (size_t i = 0; i < n; i++) {
    new (ptr + i) T();
    guard.element_constructed();
  }
  internals::mark_as_constructed(result.offset(), n * sizeof(T));
  guard.commit();
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
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T(arg);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2>
VRef<T> vnew(Arg1 arg1, Arg2 arg2) {
  VRef<T> result = VRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  VRef<T> result = VRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2, arg3);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3,
    typename Arg4>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3, Arg4 arg4) {
  VRef<T> result = VRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2, arg3, arg4);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3,
    typename Arg4, typename Arg5>
VRef<T> vnew(Arg1 arg1, Arg2 arg2, Arg3 arg3, Arg4 arg4, Arg5 arg5) {
  VRef<T> result = VRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, VRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2, arg3, arg4, arg5);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T>
struct ZRef {
private:
  struct RefCounted {
    internals::refcount_t rc;
#if __cplusplus >= 201103L
    alignas(T) char data[sizeof(T)];
#else
    union Storage {
      long double long_double_alignment;
      void *pointer_alignment;
      void (*function_pointer_alignment)();
      char data[sizeof(T)];
    } storage;
#endif
    RefCounted() : rc(1) {
    }
    char *data_ptr() {
#if __cplusplus >= 201103L
      return data;
#else
      return storage.data;
#endif
    }
  };
  internals::vaddr_t vaddr;
  static size_t data_offset() {
    RefCounted layout;
    return layout.data_ptr() - (char *) &layout;
  }
  RefCounted *refcounted() const {
    return (RefCounted *) internals::vmem.to_ptr(vaddr);
  }
  internals::refcount_t &refcount() const {
    return refcounted()->rc;
  }
  void *to_ptr() const {
    return refcounted()->data_ptr();
  }
  void destroy() {
    T *ptr = as_ptr();
    size_t count = internals::constructed_size(vaddr) / sizeof(T);
    while (count > 0)
      ptr[--count].~T();
    refcounted()->~RefCounted();
    internals::vmem_free(vaddr);
    vaddr = internals::VADDR_NULL;
  }

public:
  ZRef() : vaddr(internals::VADDR_NULL) {
  }
  ZRef(internals::vaddr_t vaddr) : vaddr(vaddr) {
  }
  operator bool() const {
    return vaddr != internals::VADDR_NULL;
  }
  bool is_null() const {
    return vaddr == internals::VADDR_NULL;
  }
  size_t offset() const {
    return vaddr;
  }
  ZRef(void *ptr) {
    if (ptr == NULL)
      vaddr = internals::VADDR_NULL;
    else
      vaddr = internals::allocated_ptr_to_vaddr((char *) ptr - data_offset());
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
  T *operator->() const {
    return (T *) to_ptr();
  }
  ZRef<T> &operator=(ZRef<T> other) {
    vaddr = other.vaddr;
    return *this;
  }
  template <typename U>
  ZRef<U> cast() const {
    return ZRef<U>(vaddr);
  }
  void retain() {
    refcount().inc(vaddr);
  }
  void release() {
    if (refcount().dec(vaddr) == 0)
      destroy();
  }
  void free() {
    destroy();
  }
  static ZRef<T> alloc(size_t n = 1) {
    internals::check_allocation_alignment<RefCounted>();
    size_t size = data_offset() + n * sizeof(T);
    if (size < sizeof(RefCounted))
      size = sizeof(RefCounted);
    internals::vaddr_t vaddr = internals::vmem_alloc(size);
    new (internals::vmem.to_ptr(vaddr)) RefCounted();
    return ZRef<T>(vaddr);
  }
};

template <typename T>
ZRef<T> znull() {
  return ZRef<T>(internals::VADDR_NULL);
}

template <typename T>
ZRef<T> znew() {
  ZRef<T> result = ZRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, ZRef<T> > guard(result, ptr);
  new (ptr) T();
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T>
ZRef<T> znew_uninitialized() {
  return ZRef<T>::alloc();
}

template <typename T>
ZRef<T> znew_array(size_t n) {
  ZRef<T> result = ZRef<T>::alloc(n);
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, ZRef<T> > guard(result, ptr);
  for (size_t i = 0; i < n; i++) {
    new (ptr + i) T();
    guard.element_constructed();
  }
  internals::mark_as_constructed(result.offset(), n * sizeof(T));
  guard.commit();
  return result;
}

template <typename T>
ZRef<T> znew_uninitialized_array(size_t n) {
  return ZRef<T>::alloc(n);
}

template <typename T, typename Arg>
ZRef<T> znew(Arg arg) {
  ZRef<T> result = ZRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, ZRef<T> > guard(result, ptr);
  new (ptr) T(arg);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2>
ZRef<T> znew(Arg1 arg1, Arg2 arg2) {
  ZRef<T> result = ZRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, ZRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

template <typename T, typename Arg1, typename Arg2, typename Arg3>
ZRef<T> znew(Arg1 arg1, Arg2 arg2, Arg3 arg3) {
  ZRef<T> result = ZRef<T>::alloc();
  T *ptr = result.as_ptr();
  internals::VMemConstructionGuard<T, ZRef<T> > guard(result, ptr);
  new (ptr) T(arg1, arg2, arg3);
  guard.element_constructed();
  internals::mark_as_constructed(result.offset(), sizeof(T));
  guard.commit();
  return result;
}

class VString {
private:
  VString(const VString &);
  VString &operator=(const VString &);
  VRef<char> _buffer;
  size_t _len;

public:
  VString(const char *s) {
    _len = std::strlen(s);
    _buffer = vnew_uninitialized_array<char>(_len + 1);
    std::strcpy(_buffer.as_ptr(), s);
  }
  VString(const char *s, size_t len) {
    _len = len;
    _buffer = vnew_uninitialized_array<char>(len + 1);
    char *buffer = _buffer.as_ptr();
    std::memcpy(buffer, s, len);
    buffer[len] = '\0';
  }
  VString(size_t len) {
    _len = len;
    _buffer = vnew_uninitialized_array<char>(len + 1);
    _buffer[len] = '\0';
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

static inline VRef<VString> vstring(size_t len) {
  return vnew<VString>(len);
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
  VRef<internals::SharedMutex> _locks;
  size_t _nbuckets;

  void _lock_bucket(size_t b) {
    _locks[b].lock();
  }
  void _unlock_bucket(size_t b) {
    _locks[b].unlock();
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
  using namespace internals;
  _nbuckets = 8;
  while (_nbuckets < size)
    _nbuckets *= 2;
  _buckets = vnew_array<VRef<Node> >(_nbuckets);
  _locks = vnew_uninitialized_array<internals::SharedMutex>(_nbuckets);
  for (size_t i = 0; i < _nbuckets; i++)
    new (_locks.as_ptr() + i) internals::SharedMutex();
  internals::mark_as_constructed(
      _locks.offset(), _nbuckets * sizeof(internals::SharedMutex));
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
  _buckets.free();
  _locks.free();
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
      if (!last.is_null()) {
        // move to front
        last->next = node_ptr->next;
        node_ptr->next = _buckets[b];
        _buckets[b] = node;
      }
      oldkey = node_ptr->key;
      oldvalue = node_ptr->value;
      if (replace) {
        node_ptr->key = key;
        node_ptr->value = value;
      }
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
      node.free();
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

class Mutex {
private:
  internals::SharedMutex _mutex;
  Mutex(const Mutex &);
  Mutex &operator=(const Mutex &);
public:
  Mutex() : _mutex(true) { }
  void lock() { _mutex.lock(); }
  void unlock() { _mutex.unlock(); }
};

class Semaphore {
private:
  internals::EventId _waiting[internals::MAX_PROCESS + 1];
  int _head, _tail;
  void next(int &index) const {
    if (index == internals::MAX_PROCESS)
      index = 0;
    else
      index++;
  }
  size_t _value;
  internals::SharedMutex _lock;
  bool _idle() const { return _head == _tail; }

public:
  explicit Semaphore(size_t value = 0) :
      _head(0), _tail(0), _value(value), _lock() { }
  size_t value();
  void post();
  bool try_wait();
  void wait();
  internals::EventSelection start_wait(
      const internals::EventId &id);
  bool stop_wait(const internals::EventId &id);
};

template <typename T>
class Queue {
private:
  struct Node {
    VRef<Node> next;
    T data;
  };
  Semaphore _incoming;
  Semaphore _outgoing;
  bool _bounded;
  internals::SharedMutex _lock;
  VRef<Node> _head, _tail;
  VRef<Node> pop() {
    VRef<Node> result = _head;
    if (_head->next.is_null()) {
      _head = _tail = vnull<Node>();
    } else {
      _head = _head->next;
    }
    return result;
  }
  void push(VRef<Node> node) {
    node->next = vnull<Node>();
    if (_tail.is_null()) {
      _head = _tail = node;
    } else {
      _tail->next = node;
      _tail = node;
    }
  }
  template <typename U>
  friend class EnqueueEvent;
  template <typename U>
  friend class DequeueEvent;

  void enqueue_nowait(T item) {
    _lock.lock();
    VRef<Node> node = vnew<Node>();
    node->data = item;
    push(node);
    _lock.unlock();
    _incoming.post();
  }
  T dequeue_nowait() {
    _lock.lock();
    VRef<Node> node = pop();
    T result;
    result = node->data;
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
  ~Queue() {
    clear();
  }
  void clear() {
    if (!_incoming.try_wait())
      return;
    do {
      _lock.lock();
      VRef<Node> node = pop();
      _lock.unlock();
      node.free();
      if (_bounded)
        _outgoing.post();
    } while (_incoming.try_wait());
  }
  void enqueue(T item) {
    if (_bounded)
      _outgoing.wait();
    enqueue_nowait(item);
  }
  bool try_enqueue(T item) {
    if (!_bounded || _outgoing.try_wait()) {
      enqueue_nowait(item);
      return true;
    } else {
      return false;
    }
  }
  T dequeue() {
    _incoming.wait();
    return dequeue_nowait();
  }
  Result<T> try_dequeue() {
    if (_incoming.try_wait())
      return Result<T>(dequeue_nowait());
    else
      return Result<T>();
  }
};

template <typename T>
class SyncVar {
private:
  internals::SharedMutex _lock;
  internals::SharedCondition _readers;
  internals::EventId _waiting[internals::MAX_PROCESS];
  size_t _waiter_count;
  bool _set;
  T _value;
  template <typename U>
  friend class SyncReadEvent;
  internals::EventSelection start_wait(
      const internals::EventId &id);
  bool stop_wait(const internals::EventId &id);
  T complete_read();
public:
  SyncVar() : _lock(), _readers(), _waiter_count(0), _set(false) { }
  T read();
  Result<T> try_read();
  bool write(T value);
  bool test();
};

template <typename T>
internals::EventSelection SyncVar<T>::start_wait(
    const internals::EventId &id) {
  _lock.lock();
  if (_set) {
    bool selected = internals::try_select(id);
    _lock.unlock();
    return selected ? internals::EventSelected
                    : internals::EventAlreadySelected;
  }
  for (size_t i = 0; i < _waiter_count; i++) {
    if (_waiting[i].process_slot == id.process_slot
        && _waiting[i].process_incarnation == id.process_incarnation
        && _waiting[i].wait_sequence_id == id.wait_sequence_id) {
      _lock.unlock();
      return internals::EventAlreadyQueued;
    }
  }
  if (_waiter_count == internals::MAX_PROCESS) {
    _lock.unlock();
    internals::pthread_fatal("SyncVar waiter queue full", EOVERFLOW);
  }
  _waiting[_waiter_count++] = id;
  _lock.unlock();
  return internals::EventQueued;
}

template <typename T>
bool SyncVar<T>::stop_wait(const internals::EventId &id) {
  _lock.lock();
  for (size_t i = 0; i < _waiter_count; i++) {
    if (_waiting[i] == id) {
      for (size_t j = i + 1; j < _waiter_count; j++)
        _waiting[j - 1] = _waiting[j];
      _waiter_count--;
      _lock.unlock();
      return true;
    }
  }
  _lock.unlock();
  return false;
}

template <typename T>
T SyncVar<T>::read() {
  _lock.lock();
  while (!_set)
    _readers.wait(_lock);
  T result = _value;
  _lock.unlock();
  return result;
}

template <typename T>
T SyncVar<T>::complete_read() {
  _lock.lock();
  assert(_set);
  T result = _value;
  _lock.unlock();
  return result;
}

template <typename T>
Result<T> SyncVar<T>::try_read() {
  _lock.lock();
  Result<T> result = _set ? Result<T>(_value) : Result<T>();
  _lock.unlock();
  return result;
}

template <typename T>
bool SyncVar<T>::write(T value) {
  _lock.lock();
  if (_set) {
    _lock.unlock();
    return false;
  }
  _value = value;
  _set = true;
  for (size_t i = 0; i < _waiter_count; i++)
    internals::try_select(_waiting[i]);
  _waiter_count = 0;
  _readers.broadcast();
  _lock.unlock();
  return true;
}

template <typename T>
bool SyncVar<T>::test() {
  _lock.lock();
  bool result = _set;
  _lock.unlock();
  return result;
}

class Event {
private:
  Event *_next;
  bool _registered;
  internals::EventId _id;
  friend class EventSet;
public:
  Event() : _next(NULL), _registered(false) { }
  virtual ~Event() { }
  virtual internals::EventSelection start_listen(
      const internals::EventId &id) = 0;
  virtual void stop_listen(const internals::EventId &id) = 0;
};

class EventSet {
private:
  Event *_head, *_tail;

public:
  EventSet() : _head(NULL), _tail(NULL) {
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

class WaitSemaphoreEvent : public Event {
private:
  VRef<Semaphore> _sem;

public:
  WaitSemaphoreEvent(VRef<Semaphore> sem) : _sem(sem) {
  }
  virtual internals::EventSelection start_listen(
      const internals::EventId &id) {
    return _sem->start_wait(id);
  }
  virtual void stop_listen(const internals::EventId &id) {
    _sem->stop_wait(id);
  }
  void complete() {
  }
};

template <typename T>
class EnqueueEvent : public Event {
private:
  VRef<Queue<T> > _queue;

public:
  EnqueueEvent(VRef<Queue<T> > queue) : _queue(queue) {
  }
  virtual internals::EventSelection start_listen(
      const internals::EventId &id) {
    if (!_queue->_bounded)
      return internals::try_select(id)
          ? internals::EventSelected
          : internals::EventAlreadySelected;
    return _queue->_outgoing.start_wait(id);
  }
  virtual void stop_listen(const internals::EventId &id) {
    if (_queue->_bounded)
      _queue->_outgoing.stop_wait(id);
  }
  void complete(T item) {
    _queue->enqueue_nowait(item);
  }
};

template <typename T>
class DequeueEvent : public Event {
private:
  VRef<Queue<T> > _queue;

public:
  DequeueEvent(VRef<Queue<T> > queue) : _queue(queue) {
  }
  virtual internals::EventSelection start_listen(
      const internals::EventId &id) {
    return _queue->_incoming.start_wait(id);
  }
  virtual void stop_listen(const internals::EventId &id) {
    _queue->_incoming.stop_wait(id);
  }
  T complete() {
    return _queue->dequeue_nowait();
  }
};

template <typename T>
class SyncReadEvent : public Event {
private:
  VRef<SyncVar<T> > _syncvar;

public:
  SyncReadEvent(VRef<SyncVar<T> > syncvar) : _syncvar(syncvar) {
  }
  virtual internals::EventSelection start_listen(
      const internals::EventId &id) {
    return _syncvar->start_wait(id);
  }
  virtual void stop_listen(const internals::EventId &id) {
    _syncvar->stop_wait(id);
  }
  T complete() {
    return _syncvar->complete_read();
  }
};

}; // namespace vspace
