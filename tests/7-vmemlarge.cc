#include "vspace.h"

using namespace vspace;

// This is a test that uses more than one segment of memory.

int main() {
  vmem_init();
  const int n = 10*1024*1024;
  Queue<int> queue = Queue<int>();
  for (int i = 0; i < n; i++)
    queue.enqueue(vnew<int>(i));
  for (int i = 0; i < n; i++)
    queue.dequeue().free();
  printf("%ld\n", vspace::internals::vmem.filesize());
  return 0;
}
