#include "test.h"

struct Tracked {
  static int next_id;
  static int expected;
  static int destroyed;
  static bool order_ok;
  int id;

  Tracked() : id(next_id++) {
  }
  ~Tracked() {
    if (id != --expected)
      order_ok = false;
    destroyed++;
  }
};

int Tracked::next_id = 0;
int Tracked::expected = 0;
int Tracked::destroyed = 0;
bool Tracked::order_ok = true;

int main() {
  using namespace vspace;
  using namespace vspace::internals;
  if (!vmem_init())
    return 1;

  VRef<Tracked> array = vnew_array<Tracked>(5);
  Tracked::expected = Tracked::next_id;
  array.free();
  if (Tracked::destroyed != 5 || !Tracked::order_ok)
    return 1;

  VRef<Tracked> raw = VRef<Tracked>::alloc(3);
  raw.free();
  if (Tracked::destroyed != 5)
    return 1;

  VRef<Tracked> single = vnew<Tracked>();
  Tracked::expected = Tracked::next_id;
  single.free();
  if (Tracked::destroyed != 6 || !Tracked::order_ok)
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
