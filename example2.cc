#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  vmem_init();
  VRef<Mutex> mutex = vnew<Mutex>();
  mutex->lock();
  mutex->unlock();
  VRef<Semaphore> sem = vnew<Semaphore>(0);
  VRef<Queue<VString> > queue = vnew<Queue<VString> >();
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process started\n");
    sleep(1);
    sem->post();
    VRef<VString> msg = vstring("Hello, world!");
    queue->enqueue(msg);
    exit(0);
  } else if (pid > 0) {
    printf("parent process resumed\n");
    sem->wait();
    VRef<VString> msg = queue->dequeue();
    printf("%d: %s\n", (int) msg->len(), msg->str());
    waitpid(pid, NULL, 0);
    msg.free();
    queue.free();
    sem.free();
    mutex.free();
  } else {
    printf("fork() failed\n");
  }
  return 0;
}