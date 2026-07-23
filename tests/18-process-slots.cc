#include "test.h"
#include <cerrno>
#include <cstdlib>
#include <sys/wait.h>

static bool wait_for_children(pid_t *children, int child_count) {
  for (int i = 0; i < child_count; i++) {
    int status;
    if (waitpid(children[i], &status, 0) != children[i]
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return false;
  }
  return true;
}

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<Semaphore> gate = vnew<Semaphore>();
  pid_t children[internals::MAX_PROCESS];
  int child_count = 0;
  const int waiting_children = internals::MAX_PROCESS - 1;

  for (int i = 0; i < waiting_children; i++) {
    pid_t child = fork_process();
    if (child == 0) {
      gate->wait();
      std::exit(0);
    }
    if (child < 0) {
      for (int j = 0; j < child_count; j++)
        gate->post();
      wait_for_children(children, child_count);
      gate.free();
      vmem_deinit();
      return 1;
    }
    children[child_count++] = child;
  }

  errno = 0;
  pid_t overflow = fork_process();
  if (overflow == 0)
    std::exit(0);
  bool exhaustion_reported = overflow == -1 && errno == EAGAIN;
  if (overflow > 0)
    children[child_count++] = overflow;

  for (int i = 0; i < waiting_children; i++)
    gate->post();
  bool children_ok = wait_for_children(children, child_count);
  gate.free();
  if (!exhaustion_reported || !children_ok) {
    vmem_deinit();
    return 1;
  }

  for (int i = 0; i < 100; i++) {
    pid_t child = fork_process();
    if (child == 0)
      std::exit(0);
    if (child < 0) {
      vmem_deinit();
      return 1;
    }
    if (!wait_for_children(&child, 1)) {
      vmem_deinit();
      return 1;
    }
  }

  vmem_deinit();
  return 0;
}
