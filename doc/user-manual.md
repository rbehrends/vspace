
VSPace is a C++ library for C++ 98 or later that supports high-level shared memory primitives in a POSIX multiprocess environment. Its basic idea was inspired by OCaml's netmulticore library.

# Table of contents

1. [Overview](#overview)
2. [Basic usage](#basic)
3. [Process handling](#processes)
4. [Virtual references](#vref)
5. [Shared strings](#vstring)
6. [Shared hash tables](#vmap)
7. [Mutexes](#mutex)
8. [Semaphores](#semaphore)
9. [Queues](#queue)
10. [Synchronization variables](#syncvar)
11. [Event sets and polling](#eventsets)

# Overview <a name="overview"></a>

In order to faciliate shared memory and interprocess communication, VSpace uses file-backed shared memory allocated by `mmap()`, which it uses to manage a shared heap that can be accessed by multiple processes concurrently.

C++ classes provide the necessary abstractions over the implementation details.

VSPace is very portable, relying only on `mmap()`, `munmap()`, file locking via `fcntl()` and `pipe()`. Where available (such as C++11 `std::atomic`), it may use alternative implementations, especially for faster locking (as `fcntl()` is comparatively slow due to always requiring a kernel call).

The basic idea is that after having initialized VSpace and having done any preparatory work that all processes rely upon, we then fork a number of worker processes that will communicate with each other or with the main process through VSpace primitives.

Worker processes can either be short-lived and terminate upon completion or continue to do work until process termination.

Various examples can be found in the `tests` directory.

# Basic usage <a name="basic"></a>

The entire library is contained in two files, `vspace.h` and `vspace.cc`. It is sufficient to add these to your project as standalone files, though you can also compile `vspace.cc` into a separate library if desired.

All public functionality is contained in the namespace `vspace`. Non-portable implementation details are contained in the namespace `vspace::internals`.

The basic skeleton for a program using VSpace looks as follows:

        #include <vspace.h>
        
        int main() {
          using namespace vspace;
          if (!vmem_init.ok()) {
            printf("could not initialize vspace shared memory");
            return 1; // error
          }
          // program body goes here.
          vmem_deinit();
          return 0;
        }

It is necessary to call `vmem_init()` before starting to use any other functionality supported by VSpace. The call to `vmem_deinit()` is optional if the program exits right afterwards. Otherwise, `vmem_deinit()` will clean up any resources used by `vmem_init()`, such as file descriptors and mapped memory. This can be done repeatedly if needed.

The result of `vmem_init()` is of type `Status`. The `ok()` method can be called to see if initialization succeeded. If not, `vmem_init().err` will contain an error code (see `vspace.h` for details) that contains the reason for why the initialization failed.

# Process handling <a name="processes"></a>

In order to do meaningful work, we will generally have to start multiple processes. For this, we provide the `fork_process()` function, which wraps the POSIX `fork()` system call and will set up interprocess communication.

Like `fork()`, `fork_process()` will return the pid of the child process in the parent process, 0 in the child process, and -1 if an error occurred. If an error occurred, `errno` will contain the error code.

A simple example demonstrates how this works ([queues](#queue) and [virtual references](#vref) are documented below).

        VRef<Queue<int> > queue = vnew<Queue<int> >(); // create a queue
        pid_t pid = fork_process();
        if (pid == 0) {
          // child process
          queue->enqueue(314);
          exit(0);
        } else if (pid > 0) {
          // parent process
          assert(queue->dequeue() == 314);
          waitpid(pid, NULL, 0); // wait for child to finish.
        } else {
          perror("fork()");
          exit(1);
        }

Note that we need to use `waitpid()` or an equivalent system call to clean up the child process.

See `tests/8-nqueens.cc` for a more complex example. 

# Virtual references <a name="vref"></a>

Virtual references are pointer analogues that reference objects in shared memory. Instead of a `T *` type for some underlying type `T`, one uses `VRef<T>`. A `VRef` type provides similar functionality to a raw pointer.

Internally, a virtual reference is represented by an offset into the file backing the shared memory, with negative offsets representing the equivalent of a null pointer. When accessed, this is translated into a pointer to the corresponding type. The translation process also ensures that memory is actually mapped.

By necessity, this process is more expensive than a standard pointer dereference. If one wishes to access the same object multiple times, one can use the `as_ptr()` and `as_ref()` methods to convert the virtual reference into a C++ pointer or reference. The resulting pointer or reference will be valid for as long as the underlying object is valid.

Virtual references support the `*`, `[]`, `->` operators in the same way that one would expect from a regular pointer. They also have an `is_null()` method to test whether this is a null reference.

New objects are created with the `vnew()` function instead of the `new` operator and are freed with the `free()` method instead of the `delete` operator. The `free()` call will call the destructor of the underlying type if there is one.

        VRef<int> v = vnew<int>(0);
        *v = *v + 1;
        printf("%d\n", *v);
        v.free();

The `vnew()` function is more limited than the `new` operator in that it can currently only support a finite number of constructor arguments (at the moment, up to 3).

There are also `vnew_uninitialized()`, `vnew_array()`, and `vnew_uninitialized_array()` functions. The "uninitialized" versions do not call constructor or otherwise initialize the memory. The "array" versions return a virtual reference that addresses an array of items. The `vnew_array()` function requires that the type has a parameterless constructor.

        const int n = 10;
        VRef<int> v = vnew_uninitialized_array<int>(n);
        int s = 0;
        for (int i = 0; i < n; i++)
          v[i] = i;
        for (int i = 0; i < n; i++)
          s += v[i];
        v.free();
        printf("%d\n", s);

Finally, the static `alloc()` method allows the allocation of raw virtual memory.

        VRef<char> buffer = VRef<char>::alloc(1024); // 1024 byte buffer.

Null references can be constructed with the `vnull()` function or be treated as a boolean, in which case they are true if and only if the virtual reference is not a null reference.

        VRef<int> v1 = vnull<int>();
        VRef<int> v2 = vnew<int>(0);
        assert(v1.is_null());
        assert(!v1);
        assert(!v2.is_null());
        assert(v2);
        v2.free();

Virtual references support a `cast()` method that allows them to be cast to another type.

        VRef<void> v = vnew<int>(0).cast<void>();
        VRef<void> v2 = v.cast<int>();

# Shared strings <a name="vstring"></a>

Shared strings are byte strings that reside in shared memory. These strings are very basic memory blocks with a start address and a length. These can be accessed with the `str()` and `len()` methods. Shared strings can be modified in place, but their length cannot be extended.

It is guaranteed that the strings returned by `str()` are null-terminated, though shared strings can also contain null bytes themselves. For convenience, they are usually constructed with the `vstring()` function, which takes either a null-terminated string or a character pointer and a length as its arguments.

        VRef<VString> alpha = vstring("alpha");
        char abc[] = { 'a', 'b', 'c' };
        VRef<VString> beta = vstring(abc, sizeof(abc));
        // It is guaranteed that `abc` is null-terminated, thus using
        // it for printf() is safe.
        printf("%s %s\n", alpha->str(), abc->str());
        printf("%d %d\n", (int) alpha->len(), (int) abc->len());

Shared strings also support a `clone()` method, which creates a copy of the string.

# Shared hash tables <a name="vmap"></a>

VSpace supports hash tables stored in shared memory. These hash tables have a fixed number of buckets and can access different buckets concurrently. Basic operations supported are adding, removing, and looking up elements. An implementation provides hash stables that implement mappings from and to shared strings; however, users can also implement hash tables for other types, including with custom hash and comparison functions.

The most basic hash table is the `VDict` class, which uses shared strings both as keys and values.

Writing to a shared hash table:

        VRef<VDict> dict = vnew<VDict>();
        VRef<VString> key = vstring("key"), value = vstring("value");
        dict->add(key, value);

The `add()` method has an optional parameter that decides whether an existing key should be overwritten; it returns `true` if a new entry was added and `false` if an existing entry was overwritten. Overwriting an entry also replaces the key:

        dict->add(key, value, true); // replace the entry
        dict->add(key, value, false); // don't replace the entry

Testing if a key is in a shared hash table:

        if (dict->find(key)) { ... }

Removing an entry from the hash table:

        dict->remove(key);

Note that removing an entry from the hash table will *not* free either the key or the value. The caller must free those explicitly if it is needed, which is not always the case (e.g. if keys or values are being reused and their lifetime ends with a function's scope).

All methods support optional parameters to obtain the original key and value:

        bool find(VRef<Key> key,
                VRef<Key> orig_key, VRef<Value> orig_value);
        bool remove(VRef<Key> key,
                VRef<Key> orig_key, VRef<Value> orig_value);
        bool add(VRef<Key> key, VRef<VString> Value,
                VRef<Key> orig_key, VRef<Value> orig_value,
                bool replace = true);

When using `find()`, `orig_key` and `orig_value` will contain the actual key and value found (note that two keys may compare as equal and still be distinct).

When using `add()`, `orig_key` and `orig_value` will contain the original key and value if they were overwritten and their values are undefined otherwise.

When using `remove()`, `orig_key` and `orig_value` will contain the removed key and value.

The `VMap<Spec>` class is a more general hash table type. The `Spec` parameter must be a struct that defines the types and static functions that paramterize the hash table:

        struct SomeSpec {
          typedef ... Key; // key type
          typedef ... Value; // value type
          static bool equal(Key *key1, Key *key2) { ... }
          static size_t hash(Key *key);
          static void free_key(VRef<Key> key) { ... }
          static void free_value(VRef<Value> value) { ... }
        };

Note that the `equal()` and `hash()` functions take pointers to `Key` instead of `VRef<Key>` arguments. The `equal()` function should return `true` iff the two keys compare as equal. The `hash()` function should return a hash value for the key.

The `free_key()` and `free_value()` functions should normally be no-ops. If they are not, then the `VMap<Spec>` destructor will use them to free keys and values. For this to be safe, the hash table generally must not contain duplicate keys or values. Neither function is used for `remove()`. When calling `remove()`, it is the caller's responsibility to free memory for keys and values.

See `tests/5-dict.cc` and `tests/6-altdict.cc` for concrete examples.

# Mutexes <a name="mutex"></a>

Mutexes implement basic lock and unlock functionality, implemented by `lock()` and `unlock()` methods. They are reentrant; for any number of `lock()` calls, there must be a matching number of `unlock()` calls.

        VRef<Mutex> mutex = vnew<Mutex>();
        mutex.lock();
        mutex.unlock();

# Semaphores <a name="semaphore"></a>

Semaphores implement standard semaphores with `post()`, `wait()`, `try_wait()` and `value()` methods. A Semaphore constructor takes an optional argument of type `size_t` that defaults to zero and is the semaphores initial value. The `wait()` method will wait until the value is non-zero, and then atomically decrement it and return. The `try_wait()` method will (as one atomic step) check if the value is non-zero and if it is non-zero, decrement it and return `true`; if it is zero, it will return false. The `post()` method will atomically increment the value. The `value()` function will return the current value of the semaphore. Note that due to race conditions, the `value()` function's primarily application is debugging, as other processes can change it right after it was queried.

Example:

        VRef<Semaphore> sem = vnew<Semaphore>(1);
        sem->wait(); // decrement counter to 0.
        assert(sem->value() == 0);
        sem->post();
        assert(sem->try_wait());
        sem->wait(); // will block until another process posts to `sem`.

# Queues <a name="queue"></a>

Queues are FIFO queues that implement basic `enqueue()`, `dequeue()`, `try_enqueue()` and `try_dequeue()` operations. Optionally, they support an upper bound on the number of elements in the queue.

The constructor of `Queue<T>` takes an optional `size_t` argument, which denotes the number of elements the queue can hold. If it is omitted or zero, the queue's capacity is only limited by available memory.

For a `Queue<T>` instance, the `enqueue()` method takes an argument of type `T` and adds it the the back of the queue. If the queue has a bounded size and adding it to the queue would exceed the size, then the operation will block until an element has been dequeued. The `try_enqueue()` is a non-blocking version, which will return true if the operation succeeded and false if `enqueue()` would have blocked.

The `dequeue()` method checks if the queue is empty. If it is empty, it will block until the queue contains at least one element. When it is not empty, it will remove the first element that was enqueued and return it. The `try_dequeue()` method is a non-blocking version that returns a `Result<T>` struct. This struct has a boolean member `ok` to signal if the dequeue operation succeeded and a `result` member that will contain the result if it was successful.

Implementation detail: the type `T` must have a default and a copy constructor. If this is not possible, one can use a `Queue<VRef<T>>` instead to wrap the type.

Example:

        // Create a bounded queue with a maximum capacity of one
        // element.
        VRef<Queue<int> > fifo = vnew<Queue<int> >(1);
        fifo.enqueue(1);
        assert(!fifo.try_enqueue(2));
        assert(fifo.dequeue() == 1);
        assert(!fifo.try_dequeue().ok);
        fifo.enqueue(2);
        Result<int> r = fifo.try_dequeue();
        assert(r.ok);
        assert(r.result == 2);

Note that processes can only send each other information that both understand. This can include pointers, but generally only if the pointers were visible to both processes before `fork_process()` was called.

Example:

        static const char *message = "Hello, parallel world!";
        VRef<Queue<const char *> > queue = vnew<Queue<const char *> >();
        pid_t pid = fork_process();
        if (pid == 0) {
          // child process
          queue->enqueue(message);
          exit(0);
        } else if (pid > 0) {
          // parent process
          printf("%s\n", queue->dequeue());
          waitpid(pid, NULL, 0); // wait for child to finish.
        } else {
          perror("fork()");
          exit(1);
        }

The above works because in both child and parent process, `messaage` has the same address. We can similarly construct large read-only data structures prior to starting worker processes and have those data structures at the same address in all processes.

If this is not possible, the data has to be packaged in a portable format (such as a struct or a `VRef<VString>`) so that both sending and receiving proces can use it.

# Synchronization variables <a name="syncvar"></a>

Synchronization variables are shared storage locations that can be written to once, read multiple times, and where reads block until the synchronization variable has been written to for the first time. The `SyncVar<T>` class has a `write()` method, which takes an argument of type `T` and writes it to the synchronization variable. It returns `true` if it was successful and `false` if the synchronization variable already contained a value, in which case the second write was ignored. The `read()` method blocks until the synchronization variable has been written to, then returns the value. The `test()` method returns `true` if the synchronization variable has been written to, `false` otherwise.

Example:

        VRef<SyncVar<int> > syncvar = vnew<SyncVar<int> >();
        pid_t pid = fork_process();
        if (pid == 0) {
          // child process
          sleep(1); // make parent block
          syncvar->write(99);
          exit(0);
        } else if (pid > 0) {
          // parent process
          printf("%s\n", syncvar->read());
          assert(syncvar->test());
          // We can now read the value as often as we like.
          assert(syncvar->read() == syncvar->read());
          waitpid(pid, NULL, 0); // wait for child to finish.
        } else {
          perror("fork()");
          exit(1);
        }

# Event sets and polling <a name="eventsets"></a>

For a number of important concurrency constructs, it is important to wait for one of out of a set of events to occur.

Examples:

* A process reading from multiple queues and merging the results into a single output queue.
* Multiple dependent processes trying alternative approaches submitted to them by a controller process through a bounded task queue. The controller needs to both wait for space to become available in the task queue and responses sent by the dependent processes.

We handle this through event sets. An event set can contain one or more events and then wait for the first of them to complete. This is similar to how the POSIX primitives `select()` and `poll()` function.

The following example illustrates the approach:

        enum Operation { HaveRead, HaveWritten };

        Operation read_or_write(VRef<Queue<int> > out, VRef<Queue<int> > in,
                int &data) {
          EventSet events;
          DequeueEvent<int> deq(in);
          EnqueueEvent<int> enq(out);
          events.add(deq);
          events.add(enq);
          switch (events.wait()) {
            case 0: // dequeue
              data = deq.complete();
              return HaveRead;
            case 1: // enqueue
              enq.complete(data);
              return HaveWritten;
          }
        }

This function tries to either read an integer from `in` or write an integer to `out`, whichever queue becomes available first.

We first declare an empty EventSet `events`.

We then declare a receive event `deq` for `in` and a send event `enq` for `out`.

Next, we call `events.wait()`. This will block until one of the events in the event set is ready. The return value of `events.wait()` is the number of the event in the order in which they were added to the event set, starting at 0. Thus, we get `0` if `deq` fired and `1` if it was `enq`.

We next need to complete the event. The reason is that the underlying object may now be in locked state and we may need to read to or write from it before it can resume normal operation. Each event type therefore supports a `complete()` operation, but the argument and return types may vary. For `EnqueueEvent`, `complete()` takes an argument that will then be enqueued in the underlying queue. For `DequeueEvent`, `complete()` takes no argument, but returns the next element in the queue.

The destructor of `EventSet` will finally do all the necessary cleanup when its scope exits.

A third event currently supported is `WaitSemaphore`, which waits for the semaphore's value to become non-zero; the `complete()` function then corresponds to a `post()` operation on the semaphore.