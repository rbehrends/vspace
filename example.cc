#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace::internals;
  vmem.init();
  const int n = 10;
  vaddr_t addr[n];
  for (int i = 0; i < n; i++) {
    addr[i] = vmem_alloc(10);
  }
  for (int i = 0; i < n; i++) {
    vmem_free(addr[i]);
  }
  for (int i = 0; i < n; i++) {
    vaddr_t a = vmem_alloc(10);
    printf("%lu\n", a);
  }
  using namespace vspace;
  VRef<Mutex> mutex = vnew<Mutex>();
  mutex->lock();
  mutex->unlock();
  VRef<Semaphore> sem = vnew<Semaphore>(0);
  VRef<Queue<VString> > queue = vnew<Queue<VString> >();
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process\n");
    sleep(1);
    sem->post();
    VRef<VString> msg = vstring("Hello, world!");
    queue->enqueue(msg);
    exit(0);
  } else if (pid > 0) {
    printf("parent process\n");
    waitpid(pid, NULL, 0);
    sem->wait();
    VRef<VString> msg = queue->dequeue();
    printf("%d: %s\n", (int) msg->len(), msg->str());
  } else {
    printf("fork() failed");
  }
  return 0;
}