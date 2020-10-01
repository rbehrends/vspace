#include "vspace.h"

int main() {
  using namespace vspace::internals;
  vmem.init();
  for (int i = 0; i < 10; i++) {
    vaddr_t addr = vmem_alloc(10);
    printf("%ld\n", addr);
  }
  return 0;
}