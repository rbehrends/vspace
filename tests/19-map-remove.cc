#include "test.h"

int main() {
  using namespace vspace;
  using namespace vspace::internals;
  if (!vmem_init())
    return 1;

  VRef<VDict> dict = vnew<VDict>();
  for (int i = 0; i < 1000; i++) {
    VRef<VString> key = vstring("key");
    VRef<VString> value = vstring("value");
    if (!dict->add(key, value))
      return 1;
    VRef<VString> oldkey, oldvalue;
    if (!dict->remove(key, oldkey, oldvalue)
        || oldkey != key || oldvalue != value)
      return 1;
    key.free();
    value.free();
  }
  dict.free();

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
