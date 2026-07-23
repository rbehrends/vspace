#include "test.h"

static bool is_mutable(char *) {
  return true;
}

static bool is_mutable(const char *) {
  return false;
}

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<VString> value = vstring("alpha");
  const VString &const_value = value.as_ref();
  bool passed = is_mutable(value->str())
      && !is_mutable(const_value.str());

  value->str()[0] = 'A';
  passed = passed
      && std::strcmp(value->str(), "Alpha") == 0
      && value->str()[value->len()] == '\0';

  value.free();
  vmem_deinit();
  return passed ? 0 : 1;
}
