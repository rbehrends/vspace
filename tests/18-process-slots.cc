#include "test.h"
#include <cstdlib>
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  for (int i = 0; i < 100; i++) {
    pid_t child = fork_process();
    if (child == 0)
      std::exit(0);
    if (child < 0)
      return 1;
    int status;
    if (waitpid(child, &status, 0) != child
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return 1;
  }

  vmem_deinit();
  return 0;
}
