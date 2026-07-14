#include "test.h"
#include <fcntl.h>
#include <stddef.h>

int main() {
  using namespace vspace;
  using namespace vspace::internals;

  char path[] = "/tmp/vspace-format-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) return 1;
  close(fd);

  if (!vmem.init(path) || vmem.current_process < 0)
    return 1;
  vmem.deinit();
  if (!vmem.init(path) || vmem.current_process < 0)
    return 1;
  vmem.deinit();

  fd = open(path, O_RDWR);
  if (fd < 0) return 1;
  uint32_t state = vspace::internals::SharedMemInitializing;
  off_t state_offset = offsetof(FileHeader, init_state);
  if (pwrite(fd, &state, sizeof(state), state_offset) != sizeof(state))
    return 1;
  close(fd);
  if (vmem.init(path).err != ErrGeneral)
    return 1;
  unlink(path);

  char old_path[] = "/tmp/vspace-old-format-XXXXXX";
  fd = mkstemp(old_path);
  if (fd < 0 || ftruncate(fd, METABLOCK_SIZE) < 0)
    return 1;
  close(fd);
  Status old_status = vmem.init(old_path);
  unlink(old_path);
  return old_status.err == ErrGeneral ? 0 : 1;
}
