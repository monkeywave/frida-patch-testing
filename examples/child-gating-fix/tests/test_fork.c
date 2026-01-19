/**
 * test_fork.c - Multi-threaded fork test for Frida child-gating
 *
 * This program creates multiple threads that continuously acquire locks,
 * then forks from the main thread. Without proper pthread_atfork handlers,
 * the child process may deadlock due to inherited locked mutexes.
 *
 * Compile: gcc -pthread -o test_fork test_fork.c
 *
 * Usage:
 *   ./test_fork              # Run standalone to verify basic functionality
 *   # Then attach with Frida using test_child_gating.py
 */

#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>

/* Mutex that will be held during fork - simulates Frida's internal locks */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* Counter to track lock acquisitions */
volatile int lock_count = 0;

void* thread_func(void* arg) {
    int thread_id = *(int*)arg;
    printf("[Thread %d] Started (TID concept)\n", thread_id);

    while (1) {
        pthread_mutex_lock(&lock);
        lock_count++;
        /* Hold the lock briefly - this window is when fork() might catch us */
        usleep(1000);  /* 1ms */
        pthread_mutex_unlock(&lock);
        /* Small sleep to allow main thread to fork */
        usleep(100);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t threads[2];
    int thread_ids[2] = {1, 2};
    int num_forks = 1;

    if (argc > 1) {
        num_forks = atoi(argv[1]);
        if (num_forks < 1) num_forks = 1;
        if (num_forks > 5) num_forks = 5;
    }

    printf("[Main] Parent PID: %d\n", getpid());
    printf("[Main] Will perform %d fork(s)\n", num_forks);
    fflush(stdout);

    /* Create worker threads that hold locks */
    for (int i = 0; i < 2; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, &thread_ids[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    /* Let threads start and begin acquiring locks */
    printf("[Main] Waiting for threads to start...\n");
    fflush(stdout);
    sleep(1);

    printf("[Main] Threads active, lock_count = %d\n", lock_count);
    fflush(stdout);

    /* Perform fork(s) - this is where deadlock can occur */
    for (int fork_num = 0; fork_num < num_forks; fork_num++) {
        printf("[Main] Calling fork() #%d...\n", fork_num + 1);
        fflush(stdout);

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            return 1;
        } else if (pid == 0) {
            /* Child process */
            printf("[Child %d] Process started (PID: %d, Parent: %d)\n",
                   fork_num + 1, getpid(), getppid());
            fflush(stdout);

            /*
             * Without the Frida fix, attempting to acquire the lock here
             * could deadlock because the lock may have been held by a thread
             * that no longer exists in the child.
             *
             * With the pthread_atfork fix, the lock is properly reinitialized.
             */
            printf("[Child %d] Attempting to acquire lock...\n", fork_num + 1);
            fflush(stdout);

            /* Try to acquire the lock - will deadlock without fix */
            pthread_mutex_lock(&lock);
            printf("[Child %d] Lock acquired successfully!\n", fork_num + 1);
            pthread_mutex_unlock(&lock);

            printf("[Child %d] Sleeping for 2 seconds...\n", fork_num + 1);
            fflush(stdout);
            sleep(2);

            printf("[Child %d] Process completed successfully\n", fork_num + 1);
            fflush(stdout);
            exit(0);
        } else {
            /* Parent process */
            printf("[Main] Forked child PID: %d\n", pid);
            fflush(stdout);
        }
    }

    /* Wait for all children */
    printf("[Main] Waiting for child processes...\n");
    fflush(stdout);

    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            printf("[Main] Child %d exited with status %d\n",
                   child_pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[Main] Child %d killed by signal %d\n",
                   child_pid, WTERMSIG(status));
        }
        fflush(stdout);
    }

    printf("[Main] All children completed, parent done\n");
    fflush(stdout);

    return 0;
}
