
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 0x01
#endif

#define MB (1024UL * 1024UL)

static void print_status(void)
{
    FILE *f;
    char line[256];

    f = fopen("/proc/self/status", "r");

    if (!f)
    {
        perror("fopen");
        return;
    }

    printf("\n=== Process Memory Status ===\n\n");

    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "Vm", 2) == 0)
        {
            printf("%s", line);
        }
    }

    fclose(f);
}

static int lock_memory(void *ptr, size_t size)
{
#if defined(__linux__) && defined(SYS_mlock2)

    printf("Trying mlock2(MLOCK_ONFAULT)...\n");

    if (syscall(SYS_mlock2, ptr, size, MLOCK_ONFAULT) == 0)
    {
        printf("mlock2(MLOCK_ONFAULT) successful\n");
        return 0;
    }

    if (errno != ENOSYS)
    {
        printf("mlock2 failed: %s\n", strerror(errno));
        return -1;
    }

    printf("mlock2 not supported, falling back to mlock()\n");

#endif

    if (mlock(ptr, size) == 0)
    {
        printf("mlock successful\n");
        return 0;
    }

    printf("mlock failed: %s\n", strerror(errno));

    return -1;
}

int main(int argc, char *argv[])
{
    size_t alloc_mb = 256;
    size_t size;
    unsigned char *ptr;

    if (argc > 1)
    {
        alloc_mb = strtoul(argv[1], NULL, 10);
    }

    size = alloc_mb * MB;

    printf("PID: %d\n", getpid());
    printf("Allocating %zu MB...\n", alloc_mb);

    ptr = (unsigned char *) mmap(NULL,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);

    if (ptr == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    /*
        Lock memory before touching pages.
        With MLOCK_ONFAULT pages become pinned lazily.
    */

    if (lock_memory(ptr, size) != 0)
    {
        printf("Memory locking failed\n");
    }

    print_status();

    printf("\nTouching memory pages...\n");

    for (size_t i = 0; i < size; i += 4096)
    {
        ptr[i] = 0xaa;

        /*
            Show gradual page locking growth every 64 MB
        */

        if ((i % (64 * MB)) == 0)
        {
            printf("Touched %zu MB\n", i / MB);
        }
    }

    printf("\nAfter touching all pages:\n");

    print_status();

    printf("\nSleeping for 120 seconds...\n");
    printf("Inspect with:\n");
    printf("  cat /proc/%d/status | grep VmLck\n", getpid());

    sleep(120);

    munlock(ptr, size);
    munmap(ptr, size);

    return 0;
}
