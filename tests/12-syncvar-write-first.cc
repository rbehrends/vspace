#include "test.h"

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<SyncVar<int> > syncvar = vnew<SyncVar<int> >();
  if (!syncvar->write(42) || syncvar->read() != 42)
    return 1;

  syncvar.free();
  vmem_deinit();
  return 0;
}
