#include "test.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<SyncVar<int> > syncvar = vnew<SyncVar<int> >();
  pid_t children[2];
  for (int i = 0; i < 2; i++) {
    children[i] = fork_process();
    if (children[i] == 0)
      _exit(syncvar->read() == 42 ? 0 : 1);
    if (children[i] < 0)
      return 1;
  }

  sleep(1);
  if (!syncvar->write(42))
    return 1;

  for (int i = 0; i < 2; i++) {
    int status;
    if (waitpid(children[i], &status, 0) < 0
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return 1;
  }

  syncvar.free();
  vmem_deinit();
  return 0;
}
