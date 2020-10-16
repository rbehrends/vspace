#include "vspace.h"

int main() {
  using namespace vspace;
  vmem_init();
  VRef<void> v = vnew<int>(0).cast<void>();
  VRef<int> v2 = v.cast<int>();
  vmem_deinit();
  return 0;
}
