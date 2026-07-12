#include "test.h"

int main() {
  using namespace vspace;
  vmem_init();
  // Mutex example
  VRef<Mutex> mutex = vnew<Mutex>();
  mutex->lock();
  mutex->unlock();
  // Create a semaphore
  VRef<Semaphore> sem = vnew<Semaphore>(0);
  // Create a queue of strings
  VRef<Queue<VRef<VString> > > queue = vnew<Queue<VRef<VString> > >();
  // Fork a process. Child processes will automatically share their
  // parent's vspace configuration. Do not use fork() in conjunction
  // with vspace, as fork_process() needs to do extra work to establish
  // interprocess communications.
  pid_t pid = fork_process();
  if (pid == 0) {
    std::printf("child process started\n");
    sleep(1);
    sem->post(); // signal the semaphore
    VRef<VString> msg = vstring("Hello, world!");
    queue->enqueue(msg); // write to queue.
    exit(0);
  } else if (pid > 0) {
    std::printf("parent process resumed\n");
    sem->wait(); // wait for semaphore
    VRef<VString> msg = queue->dequeue(); // blocking read from queue
    std::printf("%d: %s\n", (int) msg->len(), msg->str());
    waitpid(pid, NULL, 0);  // wait for child to finish.
    // free memory; while memory will be discarded automatically when
    // the last process using the shared memory exits, we do it here
    // explicitly to test that explicit freeing works properly.
    msg.free();
    queue.free();
    sem.free();
    mutex.free();
    vmem_deinit();
  } else {
    std::printf("fork() failed\n");
  }
  return 0;
}