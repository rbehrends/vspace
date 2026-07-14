#include "test.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<Mutex> mutex = vnew<Mutex>();
  VRef<int> value = vnew<int>();
  mutex->lock();
  mutex->lock();

  pid_t child = fork_process();
  if (child == 0) {
    mutex->lock();
    *value = 42;
    mutex->unlock();
    _exit(0);
  }
  if (child < 0)
    return 1;

  sleep(1);
  if (*value != 0)
    return 1;
  mutex->unlock();
  mutex->unlock();

  int status;
  if (waitpid(child, &status, 0) != child
      || !WIFEXITED(status) || WEXITSTATUS(status) != 0
      || *value != 42)
    return 1;

  value.free();
  mutex.free();
  vmem_deinit();
  return 0;
}
