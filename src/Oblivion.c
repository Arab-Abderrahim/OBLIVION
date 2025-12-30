#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <errno.h>

#define START_PORT 1
#define END_PORT 1024
#define MAX_THREADS 100
#define TIMEOUT 1
#define MAX_RESULTS 4096

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int port;
    char service[32];
    char banner[256];
} ScanResult;

/* ================= GLOBAL STATE ================= */
ScanResult results[MAX_RESULTS];
int result_count = 0;
int scanned_ports = 0;
int total_ports = END_PORT - START_PORT + 1;

pthread_mutex_t result_lock;
pthread_mutex_t progress_lock;
pthread_mutex_t print_lock;
sem_t thread_sem;

/* ================= LOGO ================= */
void print_logo() {
    printf(
"=====================================================\n"
"   ██████╗ ██████╗ ██╗     ██╗██╗   ██╗██╗ ██████╗ ███╗   ██╗\n"
"  ██╔═══██╗██╔══██╗██║     ██║██║   ██║██║██╔═══██╗████╗  ██║\n"
"  ██║   ██║██████╔╝██║     ██║██║   ██║██║██║   ██║██╔██╗ ██║\n"
"  ██║   ██║██╔══██╗██║     ██║╚██╗ ██╔╝██║██║   ██║██║╚██╗██║\n"
"  ╚██████╔╝██████╔╝███████╗██║ ╚████╔╝ ██║╚██████╔╝██║ ╚████║\n"
"   ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝\n"
"        Oblivion — Ethical Network Scanner\n"
"=====================================================\n\n"
    );
}

/* ================= SERVICE DETECTION ================= */
void detect_service(int port, char *out) {
    if (port == 80 || port == 8080) strcpy(out, "HTTP");
    else if (port == 22) strcpy(out, "SSH");
    else if (port == 21) strcpy(out, "FTP");
    else if (port == 25) strcpy(out, "SMTP");
    else if (port == 443) strcpy(out, "HTTPS");
    else strcpy(out, "UNKNOWN");
}

/* ================= BANNER SANITIZE ================= */
void sanitize(char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\n' || *s == '\r')
            *s = ' ';
    }
}

/* ================= BANNER GRAB ================= */
void grab_banner(int sock, const char *service, char *out) {
    char buf[512] = {0};

    if (!strcmp(service, "HTTP")) {
        send(sock, "GET / HTTP/1.0\r\n\r\n", 18, 0);
    }

    int r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0) {
        strncpy(out, buf, 255);
        sanitize(out);
    } else {
        strcpy(out, "No banner received");
    }
}

/* ================= SCAN THREAD ================= */
void *scan_port(void *arg) {
    char **data = (char **)arg;
    char *ip = data[0];
    int port = atoi(data[1]);

    sem_wait(&thread_sem);

    struct addrinfo hints = {0}, *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(ip, port_str, &hints, &res) != 0)
        goto cleanup;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0)
        goto cleanup_addr;

    struct timeval tv = {TIMEOUT, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) == 0) {
        ScanResult r;
        strncpy(r.ip, ip, sizeof(r.ip));
        r.port = port;
        detect_service(port, r.service);
        grab_banner(sock, r.service, r.banner);

        pthread_mutex_lock(&result_lock);
        if (result_count < MAX_RESULTS)
            results[result_count++] = r;
        pthread_mutex_unlock(&result_lock);

        pthread_mutex_lock(&print_lock);
        printf("\n[OPEN] %s:%d (%s)\n", r.ip, r.port, r.service);
        printf("------- Banner -------\n%s\n----------------------\n", r.banner);
        pthread_mutex_unlock(&print_lock);
    }

    close(sock);

cleanup_addr:
    freeaddrinfo(res);

cleanup:
    pthread_mutex_lock(&progress_lock);
    scanned_ports++;
    pthread_mutex_lock(&print_lock);
    printf("\rProgress: %.2f%%", (scanned_ports * 100.0) / total_ports);
    fflush(stdout);
    pthread_mutex_unlock(&print_lock);
    pthread_mutex_unlock(&progress_lock);

    sem_post(&thread_sem);

    free(data[0]);
    free(data[1]);
    free(data);
    return NULL;
}

/* ================= EXPORT ================= */
void export_results() {
    int choice;
    FILE *f = NULL;

    while (1) {
        printf("\n\nExport results as:\n1) TXT\n2) JSON\nChoice: ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input.\n");
            continue;
        }

        if (choice == 1) {
            f = fopen("oblivion.txt", "w");
            break;
        } else if (choice == 2) {
            f = fopen("oblivion.json", "w");
            break;
        } else {
            printf("Enter 1 or 2.\n");
        }
    }

    if (!f) {
        perror("File error");
        return;
    }

    if (choice == 2) {
        fprintf(f, "[\n");
        for (int i = 0; i < result_count; i++) {
            fprintf(f,
                "  {\"ip\":\"%s\",\"port\":%d,\"service\":\"%s\",\"banner\":\"%s\"}%s\n",
                results[i].ip,
                results[i].port,
                results[i].service,
                results[i].banner,
                (i + 1 < result_count) ? "," : ""
            );
        }
        fprintf(f, "]\n");
    } else {
        for (int i = 0; i < result_count; i++) {
            fprintf(f,
                "%s:%d\nService: %s\nBanner:\n%s\n----------------------\n",
                results[i].ip,
                results[i].port,
                results[i].service,
                results[i].banner
            );
        }
    }

    fclose(f);
    printf("\nResults exported successfully.\n");
}

/* ================= MAIN ================= */
int main() {
    print_logo();

    char target[128];
    printf("Enter target IP or IPv6: ");
    if (scanf("%127s", target) != 1) {
        printf("Invalid input.\n");
        return 1;
    }

    struct addrinfo *test = NULL;
    if (getaddrinfo(target, NULL, NULL, &test) != 0) {
        printf("Invalid IP address.\n");
        return 1;
    }
    freeaddrinfo(test);

    pthread_mutex_init(&result_lock, NULL);
    pthread_mutex_init(&progress_lock, NULL);
    pthread_mutex_init(&print_lock, NULL);
    sem_init(&thread_sem, 0, MAX_THREADS);

    pthread_t threads[total_ports];

    for (int p = START_PORT; p <= END_PORT; p++) {
        char **args = malloc(sizeof(char *) * 2);
        args[0] = strdup(target);
        args[1] = malloc(8);
        sprintf(args[1], "%d", p);

        pthread_create(&threads[p - START_PORT], NULL, scan_port, args);
    }

    for (int i = 0; i < total_ports; i++)
        pthread_join(threads[i], NULL);

    export_results();

    printf("\nScan completed successfully.\n");
    return 0;
}
