#include "test.h"
#include <sys/wait.h>

typedef vspace::VRef<vspace::VString> VStr;

int main() {
  using namespace vspace;
  vmem_init();
  VRef<VDict> dict = vnew<VDict>();
  VStr alpha = vstring("alpha");
  VStr beta = vstring("beta");
  VStr gamma = vstring("gamma");
  VStr delta = vstring("delta");
  assert(dict->add(alpha, alpha));
  assert(dict->add(beta, beta));
  assert(dict->add(gamma, gamma));
  assert(!dict->add(alpha, alpha));
  assert(dict->find(alpha));
  assert(dict->find(beta));
  assert(dict->find(gamma));
  assert(!dict->find(delta));
  std::printf("%s\n", dict->find(alpha)->str());
  std::printf("%s\n", dict->find(beta)->str());
  std::printf("%s\n", dict->find(gamma)->str());
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
  assert(dict->add(delta, delta));
  VStr k, v;
  assert(!dict->add(delta, alpha, k, v));
  assert(DictSpec::equal(v.as_ptr(), delta.as_ptr()));
  vmem_deinit();
  return 0;
}