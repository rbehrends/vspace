#include "test.h"

int main() {
  using namespace vspace;
  vmem_init();
  VRef<void> v = vnew<int>(0).cast<void>();
  VRef<int> v2 = v.cast<int>();
  v = v2.cast<void>();
  vmem_deinit();
  return 0;
}
