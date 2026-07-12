#include "test.h"

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  VRef<Queue<int> > queue = vnew<Queue<int> >();
  if (!queue->try_enqueue(1) || queue->dequeue() != 1)
    return 1;

  EventSet events;
  EnqueueEvent<int> enqueue(queue);
  events << enqueue;
  if (events.wait() != 0)
    return 1;
  enqueue.complete(2);
  if (queue->dequeue() != 2)
    return 1;

  queue.free();
  vmem_deinit();
  return 0;
}
