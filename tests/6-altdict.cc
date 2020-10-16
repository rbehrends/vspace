#include "vspace.h"
#include <sys/wait.h>

using namespace vspace;

typedef VRef<VString> VStr;

// This uses a dictionary that auto-frees content upon
// deletion. In order for this to work, no two keys and
// nodes must be shared, so we clone those.
//
// Also, remove() will *not* delete the entries. This is
// because calling code may retain ownership of keys or
// values.

struct DictSpecAutoFree : public DictSpec {
  static void free_key(VRef<Key> key) {
    key.free();
  }
  static void free_value(VRef<Key> value) {
    value.free();
  }
};

typedef VMap<DictSpecAutoFree> VDictAutoFree;

int main() {
  vmem_init();
  VRef<VDictAutoFree> dict = vnew<VDictAutoFree>();
  VStr alpha = vstring("alpha");
  VStr beta = vstring("beta");
  VStr gamma = vstring("gamma");
  VStr delta = vstring("delta");
  assert(dict->add(alpha, alpha->clone()));
  assert(dict->add(beta, beta->clone()));
  assert(dict->add(gamma, gamma->clone()));
  assert(!dict->add(alpha, alpha->clone()));
  assert(dict->find(alpha));
  assert(dict->find(beta));
  assert(dict->find(gamma));
  assert(!dict->find(delta));
  printf("%s\n", dict->find(alpha)->str());
  printf("%s\n", dict->find(beta)->str());
  printf("%s\n", dict->find(gamma)->str());
  const int n = 10000;
  VStr nstr[n];
  for (int i = 0; i < n; i++) {
    char buf[10];
    sprintf(buf, "%d", i);
    nstr[i] = vstring(buf);
    dict->add(nstr[i], nstr[i]);
  }
  for (int i = 0; i < n; i++) {
    assert(dict->find(nstr[i]) == nstr[i]);
    dict->remove(nstr[i]);
    assert(!dict->find(nstr[i]));
  }
  assert(dict->find(alpha));
  assert(dict->find(beta));
  assert(dict->find(gamma));
  assert(dict->add(delta, delta->clone()));
  VStr k, v;
  assert(!dict->add(delta, alpha, k, v));
  assert(DictSpec::equal(v.as_ptr(), delta.as_ptr()));
  dict.free();
  vmem_deinit();
  return 0;
}