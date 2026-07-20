#include "test.h"

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#define VSPACE_TEST_EXCEPTIONS 1
#endif

struct ConstructionFailure { };

struct Tracked {
  static int attempts;
  static int live;
  static int destroyed;
  static int throw_on_attempt;

  Tracked() {
    attempts++;
#ifdef VSPACE_TEST_EXCEPTIONS
    if (attempts == throw_on_attempt)
      throw ConstructionFailure();
#endif
    live++;
  }

  ~Tracked() {
    live--;
    destroyed++;
  }

  static void reset(int throw_on) {
    attempts = 0;
    live = 0;
    destroyed = 0;
    throw_on_attempt = throw_on;
  }
};

int Tracked::attempts = 0;
int Tracked::live = 0;
int Tracked::destroyed = 0;
int Tracked::throw_on_attempt = 0;

static bool allocator_is_empty() {
  using namespace vspace::internals;
  char *error = validate_allocator();
  if (error != NULL) {
    std::fprintf(stderr, "%s\n", error);
    return false;
  }
  if (vmem.metapage->segment_count == 0)
    return true;
  if (vmem.metapage->segment_count != 1
      || vmem.freelist[LOG2_SEGMENT_SIZE] != 0
      || vmem.block_ptr(0)->level() != LOG2_SEGMENT_SIZE)
    return false;
  for (int level = 0; level < LOG2_SEGMENT_SIZE; level++) {
    if (vmem.freelist[level] != VADDR_NULL)
      return false;
  }
  return true;
}

static bool test_successful_construction() {
  using namespace vspace;
  Tracked::reset(0);
  VRef<Tracked> vref = vnew_array<Tracked>(3);
  ZRef<Tracked> zref = znew_array<Tracked>(2);
  if (Tracked::attempts != 5 || Tracked::live != 5)
    return false;
  zref.free();
  vref.free();
  return Tracked::live == 0 && Tracked::destroyed == 5
      && allocator_is_empty();
}

#ifdef VSPACE_TEST_EXCEPTIONS
static bool test_vnew_failure() {
  using namespace vspace;
  Tracked::reset(1);
  try {
    vnew<Tracked>();
    return false;
  } catch (const ConstructionFailure &) {
  }
  return Tracked::attempts == 1 && Tracked::live == 0
      && Tracked::destroyed == 0 && allocator_is_empty();
}

static bool test_vnew_array_failure() {
  using namespace vspace;
  Tracked::reset(3);
  try {
    vnew_array<Tracked>(5);
    return false;
  } catch (const ConstructionFailure &) {
  }
  return Tracked::attempts == 3 && Tracked::live == 0
      && Tracked::destroyed == 2 && allocator_is_empty();
}

static bool test_znew_failure() {
  using namespace vspace;
  Tracked::reset(1);
  try {
    znew<Tracked>();
    return false;
  } catch (const ConstructionFailure &) {
  }
  return Tracked::attempts == 1 && Tracked::live == 0
      && Tracked::destroyed == 0 && allocator_is_empty();
}

static bool test_znew_array_failure() {
  using namespace vspace;
  Tracked::reset(3);
  try {
    znew_array<Tracked>(5);
    return false;
  } catch (const ConstructionFailure &) {
  }
  return Tracked::attempts == 3 && Tracked::live == 0
      && Tracked::destroyed == 2 && allocator_is_empty();
}
#endif

int main() {
  using namespace vspace;
  if (!vmem_init())
    return 1;

  bool passed = test_successful_construction();
#ifdef VSPACE_TEST_EXCEPTIONS
  passed = passed && test_vnew_failure()
      && test_vnew_array_failure()
      && test_znew_failure()
      && test_znew_array_failure();
#endif

  vmem_deinit();
  return passed ? 0 : 1;
}
