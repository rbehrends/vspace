#include "vspace.h"

using namespace vspace;

// This is a test that uses more than one segment of memory.

int main() {
  vmem_init();
  const int n = 10*1024*1024;
  VRef<Queue<VRef<int> > > queue = vnew<Queue<VRef<int> > >();
  Queue<VRef<int> > *q = queue.as_ptr();
  for (int i = 0; i < n; i++)
    q->enqueue(vnew<int>(i));
  for (int i = 0; i < n; i++)
    q->dequeue().free();
  printf("%ld\n", vspace::internals::vmem.filesize());
  vmem_deinit();
  return 0;
}
