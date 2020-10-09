#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  vmem_init();
  // Create a queue of strings
  VRef<Queue<int> > outgoing = vnew<Queue<int> >(100);
  VRef<Queue<int> > incoming = vnew<Queue<int> >();
  // Fork a process. Child processes will automatically share their
  // parent's vspace configuration. Do not use fork() in conjunction
  // with vspace, as fork_process() needs to do extra work to establish
  // interprocess communications.
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process started\n");
    int s = 0;
    for (;;) {
      VRef<int> msg = outgoing->dequeue();
      int d = *msg;
      s += d;
      msg.free();
      if (d == 0)
        break;
    }
    printf("C: %d\n", s);
    incoming->enqueue(vnew<int>(s));
    exit(0);
  } else if (pid > 0) {
    printf("parent process resumed\n");
    for (int i = 1; i <= 10000; i++) {
      outgoing->enqueue(vnew<int>(i)); // write to queue.
    }
    bool sent_sentinel = false;
    for (;;) {
      EventSet events;
      ReceiveQueue<int> recv(incoming);
      SendQueue<int> send(outgoing);
      events << recv;
      if (!sent_sentinel)
        events << send;
      switch (events.wait()) {
        case 0: { // recv
          VRef<int> msg = recv.complete();
          printf("P: %d\n", *msg);
          msg.free();
          exit(0);
          break;
        }
        case 1: { // send
          send.complete(vnew<int>(0));
          sent_sentinel = true;
          break;
        }
      }
    }
    waitpid(pid, NULL, 0); // wait for child to finish.
    // free memory; while memory will be discarded automatically when
    // the last process using the shared memory exits, we do it here
    // explicitly to test that explicit freeing works properly.
    outgoing.free();
    incoming.free();
  } else {
    printf("fork() failed\n");
  }
  return 0;
}