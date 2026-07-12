#include "test.h"

struct ZTracked {
  static int next_id;
  static int expected;
  static int destroyed;
  static bool order_ok;
  int id;

  ZTracked() : id(next_id++) {
  }
  ~ZTracked() {
    if (id != --expected)
      order_ok = false;
    destroyed++;
  }
};

int ZTracked::next_id = 0;
int ZTracked::expected = 0;
int ZTracked::destroyed = 0;
bool ZTracked::order_ok = true;

int main() {
  using namespace vspace;
  using namespace vspace::internals;
  if (!vmem_init())
    return 1;

  ZRef<int> value = znew<int>(42);
  ZRef<int> from_pointer(value.as_ptr());
  if (*value != 42 || from_pointer.offset() != value.offset())
    return 1;
  value.release();

  ZRef<long double> aligned = znew<long double>((long double) 3.5);
  if (*aligned != (long double) 3.5)
    return 1;
  aligned.release();

  ZRef<ZTracked> retained = znew<ZTracked>();
  ZTracked::expected = ZTracked::next_id;
  retained.retain();
  retained.release();
  if (ZTracked::destroyed != 0)
    return 1;
  retained.release();
  if (ZTracked::destroyed != 1 || !retained.is_null())
    return 1;

  ZRef<ZTracked> array = znew_array<ZTracked>(5);
  ZTracked::expected = ZTracked::next_id;
  array.release();
  if (ZTracked::destroyed != 6 || !ZTracked::order_ok)
    return 1;

  ZRef<ZTracked> raw = znew_uninitialized_array<ZTracked>(3);
  raw.release();
  if (ZTracked::destroyed != 6)
    return 1;

  ZRef<ZTracked> forced = znew<ZTracked>();
  ZTracked::expected = ZTracked::next_id;
  forced.free();
  if (ZTracked::destroyed != 7 || !ZTracked::order_ok)
    return 1;

  char *error = validate_allocator();
  if (error != NULL)
    std::fprintf(stderr, "%s\n", error);
  bool coalesced = error == NULL
      && vmem.metapage->segment_count == 1
      && vmem.freelist[LOG2_SEGMENT_SIZE] == 0
      && vmem.block_ptr(0)->level() == LOG2_SEGMENT_SIZE;
  vmem_deinit();
  return coalesced ? 0 : 1;
}
