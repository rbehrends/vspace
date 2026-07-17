#include "test.h"
#include <cstdlib>
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  const int child_count = 4;
  const int iterations = 100000;
  pid_t children[child_count];
  ZRef<int> value = znew<int>(42);

  for (int i = 0; i < child_count; i++) {
    value.retain();
    children[i] = fork_process();
    if (children[i] == 0) {
      for (int j = 0; j < iterations; j++) {
        value.retain();
        value.release();
      }
      value.release();
      std::exit(0);
    }
    if (children[i] < 0) {
      value.release();
      return 1;
    }
  }

  for (int i = 0; i < iterations; i++) {
    value.retain();
    value.release();
  }

  for (int i = 0; i < child_count; i++) {
    int status;
    if (waitpid(children[i], &status, 0) != children[i]
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return 1;
  }

  if (*value != 42)
    return 1;
  value.release();

  char *error = internals::validate_allocator();
  if (error != NULL)
    std::fprintf(stderr, "%s\n", error);
  vmem_deinit();
  return error == NULL ? 0 : 1;
}
