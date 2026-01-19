#!/usr/bin/env python3
"""
test_child_gating.py - Test script for Frida child-gating with patched frida-server

This script tests the child-gating functionality with the patched frida-server
that includes pthread_atfork handlers and timeout fixes.

Requirements:
    - frida-server (patched) running with root privileges
    - frida Python package installed (pip3 install frida frida-tools)
    - test_fork compiled (gcc -pthread -o test_fork test_fork.c)

Usage:
    python3 test_child_gating.py [--timeout SECONDS] [--test-binary PATH]
"""

import frida
import sys
import time
import argparse
import os
from pathlib import Path


class ChildGatingTester:
    """Test harness for Frida child-gating functionality."""

    def __init__(self, test_binary: str, timeout: int = 60):
        self.test_binary = test_binary
        self.timeout = timeout
        self.device = None
        self.session = None
        self.script = None
        self.children_detected = []
        self.children_resumed = []
        self.errors = []
        self.start_time = None

    def on_child_added(self, child):
        """Called when a child process is detected."""
        elapsed = time.time() - self.start_time
        print(f"[+] Child added at {elapsed:.2f}s:")
        print(f"    PID: {child.pid}")
        print(f"    Parent PID: {child.parent_pid}")
        print(f"    Origin: {child.origin}")
        if hasattr(child, 'path') and child.path:
            print(f"    Path: {child.path}")

        self.children_detected.append({
            'pid': child.pid,
            'parent_pid': child.parent_pid,
            'origin': str(child.origin),
            'time': elapsed
        })

        # Resume the child - with the fix, this won't hang
        try:
            print(f"[+] Resuming child {child.pid}...")
            resume_start = time.time()
            self.device.resume(child.pid)
            resume_time = time.time() - resume_start
            print(f"[+] Resumed child {child.pid} in {resume_time:.3f}s")
            self.children_resumed.append(child.pid)
        except frida.InvalidOperationError as e:
            # Child may have already exited
            print(f"[!] Could not resume child {child.pid}: {e}")
        except Exception as e:
            print(f"[!] Error resuming child {child.pid}: {e}")
            self.errors.append(str(e))

    def on_message(self, message, data):
        """Handle messages from the injected script."""
        if message['type'] == 'send':
            print(f"[Script] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[Script Error] {message['stack']}")
            self.errors.append(message['description'])
        else:
            print(f"[Script] {message}")

    def on_detached(self, reason, crash):
        """Called when the session detaches."""
        elapsed = time.time() - self.start_time
        print(f"[!] Detached at {elapsed:.2f}s: {reason}")
        if crash:
            print(f"    Crash: {crash}")

    def check_prerequisites(self):
        """Verify test prerequisites."""
        print("[*] Checking prerequisites...")

        # Check test binary exists
        if not os.path.isfile(self.test_binary):
            print(f"[!] Test binary not found: {self.test_binary}")
            print(f"    Compile with: gcc -pthread -o test_fork test_fork.c")
            return False

        if not os.access(self.test_binary, os.X_OK):
            print(f"[!] Test binary not executable: {self.test_binary}")
            return False

        # Check frida-server is running
        try:
            device = frida.get_local_device()
            processes = device.enumerate_processes()
            print(f"[+] Connected to local device, {len(processes)} processes")
        except frida.ServerNotRunningError:
            print("[!] frida-server is not running")
            print("    Start with: sudo /path/to/frida-server &")
            return False
        except Exception as e:
            print(f"[!] Cannot connect to frida: {e}")
            return False

        return True

    def run_test(self) -> bool:
        """Run the child-gating test."""
        if not self.check_prerequisites():
            return False

        self.start_time = time.time()

        try:
            # Get local device
            self.device = frida.get_local_device()
            self.device.on("child-added", self.on_child_added)

            # Spawn the test program
            print(f"[*] Spawning {self.test_binary}...")
            pid = self.device.spawn([self.test_binary])
            print(f"[*] Spawned with PID: {pid}")

            # Attach and enable child gating
            self.session = self.device.attach(pid)
            self.session.on("detached", self.on_detached)
            self.session.enable_child_gating()
            print("[*] Child gating enabled")

            # Inject instrumentation script
            self.script = self.session.create_script(self._get_instrumentation_script())
            self.script.on("message", self.on_message)
            self.script.load()

            # Resume the main process
            print("[*] Resuming main process...")
            self.device.resume(pid)

            # Wait for test to complete or timeout
            print(f"[*] Running test (timeout: {self.timeout}s)...")
            deadline = time.time() + self.timeout

            while time.time() < deadline:
                # Check if main process is still running
                try:
                    self.device.get_process(pid)
                except frida.ProcessNotFoundError:
                    print("[*] Main process exited")
                    break
                time.sleep(0.5)
            else:
                print(f"[!] Test timed out after {self.timeout}s")
                self.errors.append("Test timed out")

        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
        except Exception as e:
            print(f"[!] Error: {e}")
            self.errors.append(str(e))
            return False
        finally:
            # Cleanup
            if self.script:
                try:
                    self.script.unload()
                except:
                    pass
            if self.session:
                try:
                    self.session.detach()
                except:
                    pass

        return self._print_results()

    def _get_instrumentation_script(self) -> str:
        """Return the Frida instrumentation script."""
        return """
'use strict';

// Hook fork() to trace calls
const forkPtr = Module.findExportByName(null, 'fork');
if (forkPtr) {
    Interceptor.attach(forkPtr, {
        onEnter: function(args) {
            send('[hook] fork() called from ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n    '));
        },
        onLeave: function(retval) {
            send('[hook] fork() returned: ' + retval + ' (0 = child, >0 = parent got child PID)');
        }
    });
    send('[init] fork() hook installed');
} else {
    send('[init] WARNING: fork() not found');
}

// Hook vfork() as well
const vforkPtr = Module.findExportByName(null, 'vfork');
if (vforkPtr) {
    Interceptor.attach(vforkPtr, {
        onEnter: function(args) {
            send('[hook] vfork() called');
        },
        onLeave: function(retval) {
            send('[hook] vfork() returned: ' + retval);
        }
    });
    send('[init] vfork() hook installed');
}

// Hook clone() for completeness
const clonePtr = Module.findExportByName(null, 'clone');
if (clonePtr) {
    Interceptor.attach(clonePtr, {
        onEnter: function(args) {
            send('[hook] clone() called with flags: ' + args[0]);
        },
        onLeave: function(retval) {
            send('[hook] clone() returned: ' + retval);
        }
    });
    send('[init] clone() hook installed');
}

send('[init] All hooks installed, ready for fork events');
"""

    def _print_results(self) -> bool:
        """Print test results summary."""
        elapsed = time.time() - self.start_time

        print("\n" + "=" * 60)
        print("TEST RESULTS")
        print("=" * 60)
        print(f"Total time: {elapsed:.2f}s")
        print(f"Children detected: {len(self.children_detected)}")
        print(f"Children resumed: {len(self.children_resumed)}")
        print(f"Errors: {len(self.errors)}")

        if self.children_detected:
            print("\nChild processes:")
            for child in self.children_detected:
                resumed = "YES" if child['pid'] in self.children_resumed else "NO"
                print(f"  PID {child['pid']}: parent={child['parent_pid']}, "
                      f"origin={child['origin']}, resumed={resumed}")

        if self.errors:
            print("\nErrors encountered:")
            for error in self.errors:
                print(f"  - {error}")

        # Determine pass/fail
        success = (
            len(self.children_detected) > 0 and
            len(self.children_detected) == len(self.children_resumed) and
            len(self.errors) == 0
        )

        print("\n" + "=" * 60)
        if success:
            print("RESULT: PASS - Child-gating working correctly!")
        else:
            print("RESULT: FAIL - Issues detected")
            if len(self.children_detected) == 0:
                print("  - No child processes detected (fork may not have been called)")
            if len(self.children_detected) != len(self.children_resumed):
                print("  - Some children were not resumed (possible hang)")
        print("=" * 60)

        return success


def main():
    parser = argparse.ArgumentParser(
        description='Test Frida child-gating with patched frida-server'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=60,
        help='Test timeout in seconds (default: 60)'
    )
    parser.add_argument(
        '--test-binary', '-b',
        type=str,
        default=None,
        help='Path to test binary (default: ./test_fork)'
    )
    args = parser.parse_args()

    # Determine test binary path
    if args.test_binary:
        test_binary = args.test_binary
    else:
        # Look for test_fork in current directory or script directory
        script_dir = Path(__file__).parent
        candidates = [
            Path('./test_fork'),
            script_dir / 'test_fork',
        ]
        test_binary = None
        for candidate in candidates:
            if candidate.is_file():
                test_binary = str(candidate.absolute())
                break
        if not test_binary:
            test_binary = './test_fork'

    print("=" * 60)
    print("FRIDA CHILD-GATING TEST")
    print("=" * 60)
    print(f"Test binary: {test_binary}")
    print(f"Timeout: {args.timeout}s")
    print()

    # Check frida version
    try:
        print(f"Frida version: {frida.__version__}")
    except:
        pass
    print()

    tester = ChildGatingTester(test_binary, args.timeout)
    success = tester.run_test()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
