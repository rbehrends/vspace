#include "test.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<SyncVar<int> > value = vnew<SyncVar<int> >();
  VRef<Queue<int> > ready = vnew<Queue<int> >();
  pid_t children[2];
  for (int i = 0; i < 2; i++) {
    children[i] = fork_process();
    if (children[i] == 0) {
      EventSet events;
      SyncReadEvent<int> read(value);
      events << read;
      ready->enqueue(1);
      int selected = events.wait();
      _exit(selected == 0 && read.complete() == 42 ? 0 : 1);
    }
    if (children[i] < 0)
      return 1;
  }

  ready->dequeue();
  ready->dequeue();
  sleep(1);
  if (!value->write(42))
    return 1;

  for (int i = 0; i < 2; i++) {
    int status;
    if (waitpid(children[i], &status, 0) != children[i]
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return 1;
  }

  ready.free();
  value.free();
  vmem_deinit();
  return 0;
}
