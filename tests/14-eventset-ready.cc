#include "test.h"
#include <signal.h>
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<Queue<int> > first = vnew<Queue<int> >();
  VRef<Queue<int> > second = vnew<Queue<int> >();
  VRef<Queue<int> > ready = vnew<Queue<int> >();

  pid_t child = fork_process();
  if (child == 0) {
    EventSet events;
    DequeueEvent<int> first_event(first);
    DequeueEvent<int> second_event(second);
    events << first_event << second_event;
    ready->enqueue(1);
    int selected = events.wait();
    if (selected == 0 && first_event.complete() == 1)
      _exit(10);
    if (selected == 1 && second_event.complete() == 2)
      _exit(11);
    _exit(1);
  }
  if (child < 0)
    return 1;

  ready->dequeue();
  sleep(1);
  if (kill(child, SIGSTOP) < 0)
    return 1;
  int status;
  if (waitpid(child, &status, WUNTRACED) < 0 || !WIFSTOPPED(status))
    return 1;

  first->enqueue(1);
  second->enqueue(2);
  if (kill(child, SIGCONT) < 0 || waitpid(child, &status, 0) < 0
      || !WIFEXITED(status))
    return 1;

  bool passed = false;
  if (WEXITSTATUS(status) == 10) {
    Result<int> remaining = second->try_dequeue();
    passed = remaining.ok && remaining.result == 2;
  } else if (WEXITSTATUS(status) == 11) {
    Result<int> remaining = first->try_dequeue();
    passed = remaining.ok && remaining.result == 1;
  }

  ready.free();
  second.free();
  first.free();
  vmem_deinit();
  return passed ? 0 : 1;
}
