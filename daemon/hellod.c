#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#define FILE_PATH "/tmp/hellodaemon.txt"
#define PID_FILE  "/var/run/hello_daemon.pid"
#define INTERVAL 5  // seconds

void cleanup(int sig) {
    unlink(PID_FILE);   // remove PID file on exit
    exit(0);
}

void daemonize() {
    pid_t pid;

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); // parent exits

    // new session
    if (setsid() < 0) exit(EXIT_FAILURE);

    // fork again
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    // safe housekeeping
    umask(0);
    chdir("/");

    // close std fds
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main() {
    daemonize();

    // write PID file
    FILE *fp = fopen(PID_FILE, "w");
    if (!fp) {
        // fallback if /var/run not writable
        fp = fopen("/tmp/hello_daemon.pid", "w");
        if (!fp) exit(EXIT_FAILURE);
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    // register cleanup handler
    signal(SIGTERM, cleanup);
    signal(SIGINT, cleanup);

    unsigned long count = 1;

    while (1) {
        int fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            char buffer[64];
            int len = snprintf(buffer, sizeof(buffer), "Hello-%lu\n", count);
            write(fd, buffer, len);
            close(fd);
            count++;
        }
        sleep(INTERVAL);
    }
    
    return 0;
}
