#ifndef ROC_DAEMON_H
#define ROC_DAEMON_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

static int roc_daemon_start()
{
    int fd;

    switch (fork())
    {
    case -1:
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }
    int pid = getpid();
    printf("daemon started, pid:%d\n", pid);

    if (setsid() == -1)
    {
        return -1;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1)
    {
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1)
    {
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1)
    {
        return -1;
    }

    if (dup2(fd, STDERR_FILENO) == -1)
    {
        return -1;
    }

    if (fd > STDERR_FILENO)
    {
        if (close(fd) == -1)
        {
            return -1;
        }
    }

    return 0;
}

#endif /* ROC_DAEMON_H */
