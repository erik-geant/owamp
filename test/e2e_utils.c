/*
 *        File:         e2e_utils.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  end-to-end process utililities
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include <owamp/owamp.h>
#include <owamp/owampP.h>
#include <owampd/owampdP.h>
#include <I2util/util.h>
#include <I2util/addr.h>

#include "./owtest_utils.h"

#define NUM_TEST_PACKETS 10

#define XWAMPD_CONF_FILENAME "owamp-server.conf"
#define XWAMPD_LIMITS_FILENAME "owampd.limits"
#define XWAMPD_PFS_FILENAME "owampd.pfs"

const char USERID[] = "fake-user";
const char PASSPHRASE[] = "super secret passphrase";


/*
 * Function:        find_available_port 
 *
 * Description:     find a tcp port number that can be bound to
 *
 * In Args:
 *
 * Out Args:        the port number
 *
 * Scope:
 * Returns:         zero iff successful
 * Side Effect:
 */
int find_available_port(uint16_t *port) {
    int return_value = 1;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("error: failed to create socket!\n");
        goto cleanup;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;

    if(bind(s, (struct sockaddr *) &addr, sizeof addr) < 0) {
        perror("bind error");
        goto cleanup;
    }

    socklen_t l = sizeof addr;
    memset(&addr, 0, l);
    if(getsockname(s, (struct sockaddr *) &addr, &l)) {
        perror("getsockname error");
        goto cleanup;
    }


    *port = ntohs(addr.sin_port);
    return_value = 0;

cleanup:
    if (s > 0) {
        close(s);
    }
    return return_value;
}

/*
 * Function:        launch_owampd
 *
 * Description:     launch owampd and listen on localhost:port
 *
 * In Args:         owampd control port
 *
 * Out Args:        created temporary directory for config files
 *                  pid of owping process
 *
 * Scope:
 * Returns:         non-zero in case of error
 * Side Effect:     an owampd process is started and tmp directory
 *                  is created that should be deleted
 */
int launch_owampd(uint16_t port, char *config_dir, size_t config_dir_size, pid_t *child_pid) {

    if((*child_pid = fork()) < 0) {
        perror("fork error");
        return 1;
    }

    if (*child_pid == 0) {
        // this is the child process
        char *argv[] = {
            "../owampd/owampd",
            "-c", config_dir,
            "-R", config_dir,
            "-v",
            "-Z",
            NULL,
        };
        if (execvp(*argv, argv) < 0) {
            perror("execvp error launching owampd");
            exit(1);
        }
    }

    return 0;
}

/*
 * Function:        launch_owping 
 *
 * Description:     launch owping and point it at localhost:port
 *
 * In Args:         owampd control port, authmode (combination of AEO),
 *                  config path (not relevant for open mode)
 *
 * Out Args:        pid of owping process
 *
 * Scope:
 * Returns:         read FILE ptr opened on the subprocess's stdout
 * Side Effect:     an owping process is started
 */
FILE *launch_owping(uint16_t port, char *authmode, char *config_dir, pid_t *child_pid) {
   
    int pipefd[2];
    pipe(pipefd);
 
    if ((*child_pid = fork()) < 0) {
        perror("fork error");
        return NULL;
    }

    if (*child_pid == 0) {
        // this is the child process

        close(pipefd[0]);
        dup2(pipefd[1], fileno(stdout));
 
        char address[20];
        sprintf(address, "localhost:%d", port);
 
        char pfs_filename[PATH_MAX];
        sprintf(pfs_filename, "%s/%s", config_dir, XWAMPD_PFS_FILENAME);
 
        char num_packets[6] = {0};
        snprintf(num_packets, sizeof num_packets, "%d", NUM_TEST_PACKETS);
        char *argv[] = {
            "../owping/owping",
            "-A", authmode,
            "-u", (char *) USERID,
            "-k", pfs_filename,
            "-c", num_packets,
            address,
            NULL,
        };
        if (execvp(*argv, argv) < 0) {
            perror("execvp error launching owping");
            exit(1);
        }
    }

    close(pipefd[1]);
    return fdopen(pipefd[0], "r");
}

int create_config_dir(uint16_t *port, char *config_dir, size_t buffer_size) {

    if (buffer_size <= strlen(TMPNAME_FMT)) {
        fprintf(stderr, "dir_name buffer too small, need %lu bytes\n", strlen(TMPNAME_FMT) + 1);
        return 1;
    }

    if(find_available_port(port)) {
        fprintf(stderr, "failed to find an available port\n");
        return 1;
    }
    printf("found available port: %d, 0x%04x\n", *port, *port);

    strcpy(config_dir, TMPNAME_FMT);
    if(!mkdtemp(config_dir)) {
        perror("mkdtemp error");
        return 1; 
    }
    printf("config directory: '%s'\n", config_dir);

    char filename[PATH_MAX];
    sprintf(filename, "%s/%s", config_dir, XWAMPD_CONF_FILENAME);
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen error");
        return 1;
    } 
    fprintf(f, "srcnode localhost:%d\n", *port);
    fclose(f);


    sprintf(filename, "%s/%s", config_dir, XWAMPD_LIMITS_FILENAME);
    f = fopen(filename, "w");
    if (!f) {
        perror("fopen error");
        return 1;
    }
    fprintf(f, "limit root with disk=0, bandwidth=0, delete_on_fetch=on\n");
    fprintf(f, "limit regular with parent=root, disk=10G, bandwidth=20M\n");
    fprintf(f, "assign default regular\n");
    fclose(f);


    sprintf(filename, "%s/%s", config_dir, XWAMPD_PFS_FILENAME);
    f = fopen(filename, "w");
    if (!f) {
        perror("fopen error");
        return 1;
    }

    char *hex_passphrase = (char *) malloc(2*strlen(PASSPHRASE) + 1);
    I2HexEncode(hex_passphrase, (const uint8_t *)PASSPHRASE, strlen(PASSPHRASE));
    fprintf(f, "%s %s\n", USERID, hex_passphrase);
    free(hex_passphrase);
    fclose(f);

    return 0;
}


/*
 * Function:        main
 *
 * Description:     launch a simulated owamp server & send commands
 *                  so they can be validated in do_server (above)
 *
 * In Args:         argc, argv (unused)
 *
 * Out Args:
 *
 * Scope:           unit test (run using make check)
 * Returns:         non-zero in case of error
 * Side Effect:
 */
int e2e_test(void) {
    uint16_t port;
    char config_dir_name[PATH_MAX];

    int exit_code = 1;
    pid_t server_pid = -1, ping_pid = -1;
    FILE *owping = NULL;


    if(create_config_dir(&port, config_dir_name, sizeof(config_dir_name))) {
        printf("error initializing test config\n");
        goto cleanup;
    }

    if(launch_owampd(port, config_dir_name, sizeof config_dir_name, &server_pid)) {
        goto cleanup;
    }

    sleep(3); // give server time to startup

    if(!(owping = launch_owping(port, "O", config_dir_name, &ping_pid))) {
        goto cleanup;
    }

    int status; 
    if (waitpid(ping_pid, &status, 0) < 0) {
        perror("waitpid failed waiting for ping proc");
        goto cleanup;
    } else {

        ping_pid = -1; // i.e. don't kill below

        char output[1024];
        int len = fread(output, 1, sizeof output, owping);
        output[len] = '\0';

        printf("OWPING OUTPUT:\n%s\n", output);

        if (!status) {
            // status_str should appear in the output twice
            char status_str[20];
            snprintf(status_str, sizeof status_str, "%d sent, 0 lost", NUM_TEST_PACKETS);

            if (count_occurrences(output, status_str) == 2) {
                exit_code = 0; // succeeded
            }
        }
    }

cleanup:

    if (owping) {
        fclose(owping);
    }
    if (ping_pid > 0) {
        kill(ping_pid, SIGKILL);
        waitpid(ping_pid, &status, 0);
    }
    if (server_pid > 0) {
        kill(server_pid, SIGKILL);
        waitpid(server_pid, &status, 0);
    }

    rmdir_recursive(config_dir_name);

    return exit_code;
}

