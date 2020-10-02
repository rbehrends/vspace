#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace::internals;
  using namespace vspace;
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
  VRef<Mutex> mutex = vnew<Mutex>();
  mutex->lock();
  mutex->unlock();
  VRef<Semaphore> sem = vnew<Semaphore>(0);
  VRef<Queue<int> > queue = vnew<Queue<int> >();
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process\n");
    sleep(1);
    sem->post();
    queue->enqueue(vnew<int>(314));
  } else if (pid > 0) {
    printf("parent process\n");
    sem->wait();
    printf("%d\n", *queue->dequeue());
    waitpid(pid, NULL, 0);
  } else {
    printf("fork() failed");
  }
  return 0;
}