#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  vmem_init();
  // Create a queue of strings
  VRef<Queue<int> > queue = vnew<Queue<int> >();
  // Fork a process. Child processes will automatically share their
  // parent's vspace configuration. Do not use fork() in conjunction
  // with vspace, as fork_process() needs to do extra work to establish
  // interprocess communications.
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process started\n");
    sleep(1);
    for (int i = 1; i <= 1000; i++) {
      queue->enqueue(i); // write to queue.
    }
    queue->enqueue(0);
    exit(0);
  } else if (pid > 0) {
    printf("parent process resumed\n");
    int s = 0;
    for (;;) {
      int d = queue->dequeue();
      s += d;
      if (d == 0) break;
    }
    printf("%d\n", s);
    waitpid(pid, NULL, 0);  // wait for child to finish.
    // free memory; while memory will be discarded automatically when
    // the last process using the shared memory exits, we do it here
    // explicitly to test that explicit freeing works properly.
    queue.free();
    vmem_deinit();
  } else {
    printf("fork() failed\n");
  }
  return 0;
}