#include "test.h"

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<int> first = vnew<int>(1);
  VRef<int> original = vnew<int>(42);
  VRef<int> from_pointer(original.as_ptr());
  VRef<void> void_from_pointer(original.as_ptr());
  VRef<int> from_void = void_from_pointer.cast<int>();

  bool passed = from_pointer.offset() == original.offset()
      && from_void.offset() == original.offset()
      && *from_pointer == 42;
  original.free();
  first.free();
  vmem_deinit();
  return passed ? 0 : 1;
}
