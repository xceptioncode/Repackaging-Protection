#include <string>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <zip.h>
#include <zipint.h>
#include <aes.hpp>
#include <cstdlib>
#include <sys/mman.h>
#include <pthread.h>
#include "vendor.h"
#include "checkx.h"

#include <android/log.h>
#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "NATIVE", __VA_ARGS__);

static char * cached_path;

char *get_apk_path() {
    if(cached_path != 0) { return cached_path; }

    if (opendir("/data/data/" APK_PACKAGE_NAME "/") == NULL) {
        //printf("Tampering detected!!1!");
        return NULL;
    }

    const char *cmd = "/system/bin/pm path " APK_PACKAGE_NAME " | /system/bin/sed 's/package://'";

    FILE *fp;
    char *path = new char[1024];
    fp = popen(cmd, "r");
    if (fp == NULL) {
        //printf("Failed to run shell command");
        return NULL;
    }

    int readCnt = 0;
    while (fgets(path, 1023, fp) != NULL) {
        //printf("%s", path);
        readCnt++;
    }
    pclose(fp);

    path[strcspn(path, "\n")] = 0; // Substitute newline char by \0 so we can pass it to fopen

    if(readCnt != 1) {
        //printf("Invalid amount of apk path matches. Possible tampering detected.")
        return NULL;
    }

    return cached_path = path;
}

static int child_pid;
static bool antiDebug = false;

void *monitor_pid(void *) {

    int status;

    waitpid(child_pid, &status, 0);

    /* Child status should never change. */

    _exit(0);

}

void anti_debug() {

	if (!antiDebug) {
		antiDebug = true;
		child_pid = fork();

		if (child_pid == 0)
		{
			int ppid = getppid();
			int status;

			if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
			{
				waitpid(ppid, &status, 0);

				ptrace(PTRACE_CONT, ppid, NULL, NULL);

				while (waitpid(ppid, &status, 0)) {

					if (WIFSTOPPED(status)) {
						ptrace(PTRACE_CONT, ppid, NULL, NULL);
					} else {
						// Process has exited
						_exit(0);
					}
				}
			}

		} else {
			pthread_t t;

			/* Start the monitoring thread */

			pthread_create(&t, NULL, monitor_pid, (void *)NULL);
		}
	}
}

static bool antiDebug1 = false;

void *anti_debug1(void *argv) {
	const int bufsize = 2048;
    char filename[bufsize];
    char line[bufsize];
    int pid = getpid();
    sprintf(filename, "/proc/%d/status", pid);
    FILE* fd;
    while (1) {
        fd = fopen(filename, "r");
            if (fd != NULL) {
                while (fgets(line, bufsize, fd)) {
                    if (strncmp(line, "TracerPid", 9) == 0) {
                        int currentId = atoi(&line[10]);
						//printf("Tracing DETECTED: %d ", currentId);
                        if (currentId != 0) {
							//printf("KILLING ... ");
                            fclose(fd);
                            int ret = kill(pid, SIGKILL);
                            exit(-1);
                        }
                        break;
                    }
                }
                fclose(fd);
            }
        sleep(10);
    }
    return ((void *) 0);
}

void anti_debug_traceid() {
	if (!antiDebug1) {
		antiDebug1 = true;
		pthread_t t_id;
		int err = pthread_create(&t_id, NULL, anti_debug1, NULL);
		if (err != 0) {
			//printf("create thread fail: %s\n", strerror(err));
		}
	}
}

int decrypt_code(void *offset, size_t count, const unsigned char *key) {
    int page_size = getpagesize();

    char *page_start = ((char *)offset) - (((unsigned long)offset) % page_size);
    size_t page_count = 1; // Pages to mprotect
    while(((char *)offset) + count > (page_start + page_size * page_count)) {
        page_count++;
    }

    if(mprotect(page_start, page_count * page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        //printf("Err mprotect\n");
        return -1;
    } else {
        //printf("Ok mprotect\n");
    }

    struct AES_ctx ctx;
    const size_t chk_size = 16;
    uint8_t iv[chk_size];
    memset(iv, 0, chk_size);

    AES_init_ctx_iv(&ctx, key, iv);

    const size_t direct_buffer_size = count - (count % chk_size);
    if(direct_buffer_size > 0) {
        AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)offset, direct_buffer_size);
    }

    //printf("Directly decrypted %d bytes\n", direct_buffer_size);

    uint8_t buf[chk_size];
    if(count - direct_buffer_size > 0) {
        char *remaining_offset = ((char *)offset) + direct_buffer_size;
        int remaining_count = count - direct_buffer_size;
        //printf("Decrypted remaining %d bytes (offset=%p) that didn't fit AES chunk of size %d\n", remaining_count, remaining_offset, chk_size);
        memcpy(buf, remaining_offset, remaining_count); // Read memory of last chunk into buf
        AES_CTR_xcrypt_buffer(&ctx, buf, chk_size); // XOR entire chunk with stream cipher (we ignore part after count)
        memcpy(remaining_offset, buf, remaining_count); // Write decrypted memory back into .text segment
    }

    // Clean instruction cache
    __builtin___clear_cache(page_start, page_start + (page_count * page_size));
    return 0;
}