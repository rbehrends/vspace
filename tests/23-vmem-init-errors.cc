#include "test.h"
#include <fcntl.h>

int main() {
  using namespace vspace;
  using namespace vspace::internals;

  if (vmem.init(-1).err != ErrOS)
    return 1;

  char empty_path[] = "/tmp/vspace-empty-XXXXXX";
  int fd = mkstemp(empty_path);
  if (fd < 0)
    return 1;
  close(fd);
  fd = open(empty_path, O_RDONLY);
  if (fd < 0)
    return 1;
  Status status = vmem.init(fd);
  close(fd);
  unlink(empty_path);
  if (status.err != ErrOS)
    return 1;

  char short_path[] = "/tmp/vspace-short-XXXXXX";
  fd = mkstemp(short_path);
  if (fd < 0 || ftruncate(fd, 1) < 0)
    return 1;
  close(fd);
  fd = open(short_path, O_RDONLY);
  if (fd < 0)
    return 1;
  status = vmem.init(fd);
  close(fd);
  unlink(short_path);
  if (status.err != ErrMMap)
    return 1;

  if (!vmem_init())
    return 1;
  vmem_deinit();
  return 0;
}
