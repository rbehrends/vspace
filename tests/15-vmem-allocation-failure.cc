#include "test.h"
#include <sys/wait.h>

static void allocation_failed(size_t size) {
  _exit(size == vspace::internals::SEGMENT_SIZE ? 42 : 1);
}

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  internals::vaddr_t allocation = internals::vmem_alloc(16 * 1024 * 1024);
  internals::vmem_free(allocation);

  set_allocation_failure_handler(allocation_failed);
  pid_t child = fork_process();
  if (child == 0)
    internals::vmem_alloc(internals::SEGMENT_SIZE);
  if (child < 0)
    return 1;

  int status;
  bool passed = waitpid(child, &status, 0) == child
      && WIFEXITED(status) && WEXITSTATUS(status) == 42;
  set_allocation_failure_handler(NULL);
  vmem_deinit();
  return passed ? 0 : 1;
}
