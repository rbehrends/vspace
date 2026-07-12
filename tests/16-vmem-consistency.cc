#include "test.h"

static bool allocator_is_valid() {
  char *error = vspace::internals::validate_allocator();
  if (error != NULL)
    std::fprintf(stderr, "%s\n", error);
  return error == NULL;
}

int main() {
  using namespace vspace;
  using namespace vspace::internals;
  if (!vmem_init() || !allocator_is_valid())
    return 1;

  vaddr_t one = vmem_alloc(1);
  if (!allocator_is_valid())
    return 1;
  vmem_free(one);
  if (!allocator_is_valid()
      || vmem.freelist[LOG2_SEGMENT_SIZE] != 0
      || vmem.block_ptr(0)->level() != LOG2_SEGMENT_SIZE)
    return 1;
  for (int level = 0; level < LOG2_SEGMENT_SIZE; level++) {
    if (vmem.freelist[level] != VADDR_NULL)
      return 1;
  }

  const size_t sizes[] = { 1, 33, 1000, 65536, 1024 * 1024, 17, 4096 };
  const int count = sizeof(sizes) / sizeof(sizes[0]);
  vaddr_t allocations[count];
  for (int i = 0; i < count; i++) {
    allocations[i] = vmem_alloc(sizes[i]);
    if (!allocator_is_valid())
      return 1;
  }

  const int order[] = { 3, 0, 5, 2, 6, 1, 4 };
  for (int i = 0; i < count; i++) {
    vmem_free(allocations[order[i]]);
    if (!allocator_is_valid())
      return 1;
  }

  bool coalesced = vmem.metapage->segment_count == 1
      && vmem.freelist[LOG2_SEGMENT_SIZE] == 0
      && vmem.block_ptr(0)->level() == LOG2_SEGMENT_SIZE;
  vmem_deinit();
  return coalesced ? 0 : 1;
}
