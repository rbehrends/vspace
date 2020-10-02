#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace::internals;
  vmem.init();
  const int n = 10;
  vaddr_t addr[n];
  for (int i = 0; i < n; i++) {
    addr[i] = vmem_alloc(10);
  }
  for (int i = 0; i < n; i++) {
    vmem_free(addr[i]);
  }
  for (int i = 0; i < n; i++) {
    vaddr_t a = vmem_alloc(10);
    printf("%lu\n", a);
  }
  return 0;
}