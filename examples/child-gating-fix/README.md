# Child-Gating Freeze Fix Example

This example demonstrates how to use the Frida Patch Testing Framework to build
a modified Frida that fixes the child-gating freeze issue on Linux.

## The Problem

When using Frida's child-gating feature on Linux, the traced process can freeze
indefinitely under certain conditions:

1. **fork() with held locks**: If the parent process holds pthread locks during
   fork(), the child inherits these locks in a locked state. If the lock holder
   thread wasn't forked, the locks are never released.

2. **Frida agent waiting**: Frida's agent may wait indefinitely for the child
   process to reach a certain state, but the child is deadlocked.

3. **Infinite DBus timeout**: The DBus proxy timeout is set to `int.MAX` when
   calling `wait_for_permission_to_resume()`, which can block forever if the
   controller doesn't respond.

## The Fix

This example includes two patches that work together to solve these issues:

### frida-gum patch (0001-interceptor-add-pthread-atfork-handlers.patch)

Adds `pthread_atfork()` handlers to properly manage lock state across fork:

- **prepare**: Acquires `_gum_interceptor_lock` and the thread context spinlock
  before fork to ensure consistent state
- **parent**: Releases both locks after fork completes in parent
- **child**: Reinitializes both locks (they may have been held by threads that
  no longer exist) and clears the thread contexts hash table since all threads
  except the forking thread cease to exist

This ensures fork safety for applications using Frida instrumentation that need
to fork child processes.

### frida-core patch (0001-agent-add-timeout-to-child-gating-wait.patch)

Adds configurable timeouts to prevent indefinite hangs:

- Replaces `int.MAX` timeout with a 30-second timeout for DBus calls
- Adds timeout-based waiting using `wait_until()` with `GLib.get_monotonic_time()`
- Logs warnings when timeouts occur instead of hanging
- Continues execution gracefully after timeout to prevent deadlocks

This is particularly important for scenarios where:
- The Frida host disconnects during a fork operation
- Network issues prevent the controller from responding
- The controller crashes or becomes unresponsive

## Usage

### Quick Start

```bash
# From the frida-patch-testing directory:

# 1. Copy this example's config
cp examples/child-gating-fix/config.yaml config.yaml

# 2. Copy the patches
cp -r examples/child-gating-fix/patches/* patches/

# 3. Build
./build/run.sh
```

### Manual Setup

1. Copy the patches to the appropriate directories:
   ```bash
   cp examples/child-gating-fix/patches/frida-gum/*.patch patches/frida-gum/
   cp examples/child-gating-fix/patches/frida-core/*.patch patches/frida-core/
   ```

2. Create or modify your config.yaml to enable patches for these components

3. Run the build

## Testing the Fix

After building, test with a multi-threaded application that uses fork():

```python
import frida

def on_child_added(child):
    print(f"Child added: {child.pid}")
    # With the fix, this won't hang
    session.resume(child.pid)

session = frida.attach("target-process")
session.enable_child_gating()
session.on("child-added", on_child_added)
```

### Test Scenario: Multi-threaded Fork

Create a test program that:
1. Spawns multiple threads that acquire locks
2. Forks from the main thread while locks are held
3. The child process should not deadlock with the patched Frida

```c
// test_fork.c - Compile with: gcc -pthread -o test_fork test_fork.c
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void* thread_func(void* arg) {
    while (1) {
        pthread_mutex_lock(&lock);
        usleep(1000);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);

    sleep(1);  // Let thread start

    pid_t pid = fork();
    if (pid == 0) {
        // Child - without the fix, this could deadlock
        printf("Child process running\n");
        sleep(2);
        printf("Child process done\n");
    } else {
        printf("Parent waiting for child\n");
        wait(NULL);
        printf("Parent done\n");
    }
    return 0;
}
```

## Patches Included

| File | Description |
|------|-------------|
| `patches/frida-gum/0001-interceptor-add-pthread-atfork-handlers.patch` | Handles lock management across fork() |
| `patches/frida-core/0001-agent-add-timeout-to-child-gating-wait.patch` | Adds timeout to prevent infinite hangs |

## Technical Details

### pthread_atfork() Mechanism

The `pthread_atfork()` function registers handlers that are called at specific
points during a fork:

```
Parent process:
  1. prepare() - called before fork
  2. fork() system call
  3. parent() - called after fork in parent

Child process:
  1. (inherits prepare() state)
  2. fork() system call
  3. child() - called after fork in child
```

### Timeout Constants

The timeout is defined in the frida-core patch:

```vala
private const int CHILD_GATING_TIMEOUT_SEC = 30;
private const int CHILD_GATING_TIMEOUT_MSEC = CHILD_GATING_TIMEOUT_SEC * 1000;
```

You can modify this value if you need longer or shorter timeouts for your use case.

## Related Issues

- Frida Issue: Child-gating causes process freeze on Linux
- Root cause: pthread mutex state not properly handled across fork()
- Additional cause: Infinite timeout in DBus wait operations

## Compatibility

These patches have been tested with:
- Frida 16.x
- Linux (glibc and musl)
- FreeBSD
- macOS (Darwin)

The patches include compile-time guards for platform-specific code:
```c
#if defined (HAVE_LINUX) || defined (HAVE_FREEBSD) || defined (HAVE_QNX) || \
    defined (HAVE_DARWIN)
```
