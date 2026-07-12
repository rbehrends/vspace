#include "test.h"

struct Counted {
  vspace::VRef<int> counter;

  Counted() : counter() {
  }
  Counted(vspace::VRef<int> counter) : counter(counter) {
  }
  ~Counted() {
    if (!counter.is_null())
      ++*counter;
  }
};

int main() {
  using namespace vspace;
  using namespace vspace::internals;
  if (!vmem_init())
    return 1;

  bool passed = true;
  VRef<int> counter = vnew<int>(0);
  {
    VRef<Queue<Counted> > queue = vnew<Queue<Counted> >(2);
    Counted item(counter);

    queue->clear();
    queue->enqueue(item);
    int before = *counter;
    queue->clear();
    passed = passed && *counter == before + 1
        && !queue->try_dequeue().ok;

    queue->enqueue(item);
    before = *counter;
    queue.free();
    passed = passed && *counter == before + 1;
  }
  counter.free();

  char *error = validate_allocator();
  if (error != NULL)
    std::fprintf(stderr, "%s\n", error);
  passed = passed && error == NULL
      && vmem.metapage->segment_count == 1
      && vmem.freelist[LOG2_SEGMENT_SIZE] == 0
      && vmem.block_ptr(0)->level() == LOG2_SEGMENT_SIZE;
  vmem_deinit();
  return passed ? 0 : 1;
}
