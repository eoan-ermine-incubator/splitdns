#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <string.h>

int main(void) {
    auto mq = mq_open("/eoanermine_splitdns", O_WRONLY);

    if (mq == (mqd_t)-1) {
        perror("mq_open");
        return EXIT_FAILURE;
    }

    const char *msg = "Hello from Process A";

    if (mq_send(mq, msg, strlen(msg) + 1, 0) == -1) {
        perror("mq_send");
        mq_close(mq);
        return EXIT_FAILURE;
    }

    mq_close(mq);
    return EXIT_SUCCESS;
}