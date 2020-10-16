#include "vspace.h"
#include <sys/wait.h>

int main() {
  using namespace vspace;
  vmem_init();
  VRef<SyncVar<VRef<VString> > > syncvar = vnew<SyncVar<VRef<VString> > >();
  // Fork a process. Child processes will automatically share their
  // parent's vspace configuration. Do not use fork() in conjunction
  // with vspace, as fork_process() needs to do extra work to establish
  // interprocess communications.
  pid_t pid = fork_process();
  if (pid == 0) {
    printf("child process started\n");
    sleep(1);
    VRef<VString> msg = vstring("Hello, world!");
    syncvar->write(msg);
    exit(0);
  } else if (pid > 0) {
    printf("parent process resumed\n");
    printf("%d: %s\n", (int) syncvar->read()->len(), syncvar->read()->str());
    waitpid(pid, NULL, 0);  // wait for child to finish.
    // free memory; while memory will be discarded automatically when
    // the last process using the shared memory exits, we do it here
    // explicitly to test that explicit freeing works properly.
    syncvar.free();
    vmem_deinit();
  } else {
    printf("fork() failed\n");
  }
  return 0;
}