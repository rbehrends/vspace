#include "test.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<Queue<int> > exact_queue = vnew<Queue<int> >();
  exact_queue->enqueue(17);
  DequeueEvent<int> exact_event(exact_queue);
  EventSet exact_events;
  exact_events << exact_event << exact_event;
  if (exact_events.wait() != 0 || exact_event.complete() != 17)
    return 1;

  VRef<Queue<int> > queue = vnew<Queue<int> >();
  VRef<SyncVar<int> > syncvar = vnew<SyncVar<int> >();
  VRef<Queue<int> > ready = vnew<Queue<int> >();

  pid_t child = fork_process();
  if (child == 0) {
    DequeueEvent<int> first_queue_event(queue);
    DequeueEvent<int> second_queue_event(queue);
    EventSet queue_events;
    queue_events << first_queue_event << second_queue_event;
    ready->enqueue(1);
    if (queue_events.wait() != 0 || first_queue_event.complete() != 23)
      _exit(1);

    SyncReadEvent<int> first_sync_event(syncvar);
    SyncReadEvent<int> second_sync_event(syncvar);
    EventSet sync_events;
    sync_events << first_sync_event << second_sync_event;
    ready->enqueue(2);
    if (sync_events.wait() != 0 || first_sync_event.complete() != 29)
      _exit(1);
    _exit(0);
  }
  if (child < 0)
    return 1;

  if (ready->dequeue() != 1)
    return 1;
  sleep(1);
  queue->enqueue(23);

  if (ready->dequeue() != 2)
    return 1;
  sleep(1);
  if (!syncvar->write(29))
    return 1;

  int status;
  bool passed = waitpid(child, &status, 0) == child
      && WIFEXITED(status) && WEXITSTATUS(status) == 0;

  ready.free();
  syncvar.free();
  queue.free();
  exact_queue.free();
  vmem_deinit();
  return passed ? 0 : 1;
}
