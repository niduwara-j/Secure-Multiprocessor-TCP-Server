#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#define PORT 50423
#define MAX_BUF 8192
#define MAX_PAYLOAD 4096

#define SID "1024"
#define REGNO "IT24102423"
#define LOG_FILE "server_IT24102423.log"
#define DATA_DIR "./data/"

// ANSI Color Codes
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

// ---------------- SIGCHLD HANDLER (ZOMBIE PREVENTION) ----------------
void sigchld_handler(int s) {
    (void)s;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// ---------------- UTILITIES ----------------
char *random_string(int len) {
    char *str = malloc(len + 1);
    if (!str) return NULL;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < len; i++) {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[len] = '\0';
    return str;
}

char *hash_password(const char *pass) {
    char salt[32] = "$6$";
    char *rand_salt = random_string(16);
    if (!rand_salt) return NULL;
    strcat(salt, rand_salt);
    free(rand_salt);
    char *hashed = crypt(pass, salt);
    return hashed ? strdup(hashed) : NULL;
}

int valid_username(const char *u) {
    if (!u) return 0;
    size_t len = strlen(u);
    if (len < 3 || len > 20) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(u[i]) && u[i] != '_') return 0;
    }
    return 1;
}

// ---------------- LOGGING ----------------
void log_event(const char *ip, int port, pid_t pid,
               const char *user, const char *cmd, const char *result) {

    FILE *f = fopen(LOG_FILE, "a");
    time_t now = time(NULL);
    char t[64];
    strftime(t, sizeof(t), "%Y-%m-%d %H:%M:%S", localtime(&now));

    const char *username = (user && strlen(user) > 0) ? user : "none";

    // Write to audit log file
    if (f) {
        fprintf(f, "[%s] IP:%s:%d PID:%d User:%s Cmd:%s Result:%s\n",
                t, ip, port, pid, username, cmd, result);
        fclose(f);
    }

    // Print styled log to server console
    const char *status_color = COLOR_GREEN;
    if (strcmp(result, "ERR") == 0 || strcmp(result, "FAIL") == 0) {
        status_color = COLOR_RED;
    } else if (strcmp(result, "LOCKED") == 0) {
        status_color = COLOR_YELLOW;
    }

    printf(COLOR_CYAN "[%s]" COLOR_RESET " " COLOR_BLUE "%s:%d" COLOR_RESET
           " (PID:%d) [" COLOR_MAGENTA "%s" COLOR_RESET "] %s -> %s%s%s\n",
           t, ip, port, pid, username, cmd, status_color, result, COLOR_RESET);
    fflush(stdout);
}

// ---------------- RESPONSE BUILDER ----------------
void send_resp(int sock, const char *type, int code, const char *msg) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s %d SID:%s %s\n", type, code, SID, msg);
    send(sock, buf, strlen(buf), 0);
}

// ---------------- AUTHENTICATION ----------------
int register_user(const char *user, const char *pass) {
    if (!valid_username(user) || !pass || strlen(pass) == 0) return -1;

    char path[256];
    snprintf(path, sizeof(path), "%s%s.pass", DATA_DIR, user);

    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return -1; } // User already exists

    f = fopen(path, "w");
    if (!f) return -1;

    char *hash = hash_password(pass);
    if (!hash) {
        fclose(f);
        return -1;
    }
    fprintf(f, "%s\n", hash);
    free(hash);
    fclose(f);

    return 0;
}

int check_login(const char *user, const char *pass) {
    if (!user || !pass) return 0;

    char path[256];
    snprintf(path, sizeof(path), "%s%s.pass", DATA_DIR, user);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char stored[256];
    if (!fgets(stored, sizeof(stored), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    stored[strcspn(stored, "\r\n")] = 0;

    char *hash = crypt(pass, stored);
    return (hash && strcmp(hash, stored) == 0);
}

// ---------------- FAILED ATTEMPTS & ACCOUNT LOCKOUT ----------------
int get_fail_count(const char *user) {
    if (!user) return 0;
    char path[256];
    snprintf(path, sizeof(path), "%s%s.fail", DATA_DIR, user);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int c = 0;
    if (fscanf(f, "%d", &c) != 1) {
        c = 0;
    }
    fclose(f);
    return c;
}

void increment_fail(const char *user) {
    if (!user) return;
    char path[256];
    snprintf(path, sizeof(path), "%s%s.fail", DATA_DIR, user);

    int c = get_fail_count(user) + 1;

    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d", c);
        fclose(f);
    }

    if (c >= 3) {
        char lock[256];
        snprintf(lock, sizeof(lock), "%s%s.lock", DATA_DIR, user);
        FILE *lf = fopen(lock, "w");
        if (lf) fclose(lf);
    }
}

int is_locked(const char *user) {
    if (!user) return 0;
    char lock[256];
    snprintf(lock, sizeof(lock), "%s%s.lock", DATA_DIR, user);
    return access(lock, F_OK) == 0;
}

void reset_fail(const char *user) {
    if (!user) return;
    char path[256];
    snprintf(path, sizeof(path), "%s%s.fail", DATA_DIR, user);
    unlink(path);

    char lock[256];
    snprintf(lock, sizeof(lock), "%s%s.lock", DATA_DIR, user);
    unlink(lock);
}

// ---------------- COMMAND PROCESSOR ----------------
void process_cmd(char *cmd, int sock,
                 char *user, char *token,
                 time_t *last_activity,
                 const char *ip, int port) {

    // Session inactivity timeout (300 seconds / 5 minutes)
    if (strlen(user) > 0 && (time(NULL) - *last_activity > 300)) {
        user[0] = '\0';
        token[0] = '\0';
    }

    *last_activity = time(NULL);

    char original[MAX_PAYLOAD + 1];
    strncpy(original, cmd, sizeof(original) - 1);
    original[sizeof(original) - 1] = '\0';

    char *c = strtok(cmd, " ");
    if (!c) return;

    // REGISTER <user> <password>
    if (strcmp(c, "REGISTER") == 0) {
        char *u = strtok(NULL, " ");
        char *p = strtok(NULL, " ");

        if (!u || !p) {
            send_resp(sock, "ERR", 400, "Missing arguments");
            log_event(ip, port, getpid(), user, original, "ERR");
            return;
        }

        if (register_user(u, p) == 0) {
            send_resp(sock, "OK", 200, "Registration successful");
            log_event(ip, port, getpid(), user, original, "OK");
        } else {
            send_resp(sock, "ERR", 409, "Registration failed or user already exists");
            log_event(ip, port, getpid(), user, original, "ERR");
        }
    }

    // LOGIN <user> <password>
    else if (strcmp(c, "LOGIN") == 0) {
        char *u = strtok(NULL, " ");
        char *p = strtok(NULL, " ");

        if (!u || !p) {
            send_resp(sock, "ERR", 400, "Missing arguments");
            log_event(ip, port, getpid(), user, original, "ERR");
            return;
        }

        if (is_locked(u)) {
            send_resp(sock, "ERR", 423, "Account locked - maximum attempts exceeded");
            log_event(ip, port, getpid(), user, original, "LOCKED");
            return;
        }

        if (check_login(u, p)) {
            strncpy(user, u, 63);
            user[63] = '\0';

            char *t = random_string(32);
            if (t) {
                strncpy(token, t, 63);
                token[63] = '\0';
                free(t);
            }

            reset_fail(u);

            char msg[256];
            snprintf(msg, sizeof(msg), "Login successful. Token: %s", token);

            send_resp(sock, "OK", 200, msg);
            log_event(ip, port, getpid(), user, original, "OK");
        } else {
            increment_fail(u);
            send_resp(sock, "ERR", 401, "Invalid credentials");
            log_event(ip, port, getpid(), user, original, "FAIL");
        }
    }

    // STATUS
    else if (strcmp(c, "STATUS") == 0) {
        if (strlen(user) == 0) {
            send_resp(sock, "ERR", 401, "Not logged in");
            log_event(ip, port, getpid(), user, original, "ERR");
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "User: %s (Active Session)", user);
            send_resp(sock, "OK", 200, msg);
            log_event(ip, port, getpid(), user, original, "OK");
        }
    }

    // LOGOUT [token]
    else if (strcmp(c, "LOGOUT") == 0) {
        char *tok = strtok(NULL, " ");
        if (strlen(user) == 0) {
            send_resp(sock, "ERR", 401, "Not logged in");
            log_event(ip, port, getpid(), "none", original, "ERR");
            return;
        }

        if (tok && strlen(token) > 0 && strcmp(token, tok) != 0) {
            send_resp(sock, "ERR", 401, "Invalid session token");
            log_event(ip, port, getpid(), user, original, "ERR");
            return;
        }

        user[0] = '\0';
        token[0] = '\0';
        send_resp(sock, "OK", 200, "Logout successful");
        log_event(ip, port, getpid(), "none", original, "OK");
    }

    // UNKNOWN
    else {
        send_resp(sock, "ERR", 404, "Unknown command");
        log_event(ip, port, getpid(), user, original, "ERR");
    }
}

// ---------------- CLIENT SESSION HANDLER ----------------
void handle_client(int sock, const char *ip, int port) {
    char buffer[MAX_BUF];
    int offset = 0;

    char user[64] = {0};
    char token[64] = {0};
    time_t last_activity = time(NULL);

    int req_count = 0;
    time_t window_start = time(NULL);

    while (1) {
        int n = recv(sock, buffer + offset, sizeof(buffer) - offset - 1, 0);
        if (n <= 0) break;

        offset += n;
        buffer[offset] = '\0';

        while (1) {
            char *newline = strstr(buffer, "\n");
            if (!newline) break; // Incomplete header, need more data

            if (strncmp(buffer, "LEN:", 4) != 0) {
                send_resp(sock, "ERR", 400, "Malformed protocol header");
                close(sock);
                return;
            }

            int len = atoi(buffer + 4);
            char *payload = newline + 1;

            if (len <= 0 || len > MAX_PAYLOAD) {
                send_resp(sock, "ERR", 413, "Payload length out of bounds");
                close(sock);
                return;
            }

            // Check if full payload has arrived
            int header_len = (payload - buffer);
            if (offset < header_len + len) {
                break; // Incomplete payload, wait for more chunks
            }

            // Rate limiter: Max 10 requests per 60 seconds per connection
            time_t now = time(NULL);
            if (now - window_start >= 60) {
                req_count = 0;
                window_start = now;
            }
            req_count++;

            if (req_count > 10) {
                send_resp(sock, "ERR", 429, "Rate limit exceeded (Max 10 req/min)");
                log_event(ip, port, getpid(), user, "RATE_LIMIT", "ERR");
                close(sock);
                return;
            }

            // Extract message safely
            char msg[MAX_PAYLOAD + 1];
            memcpy(msg, payload, len);
            msg[len] = '\0';

            process_cmd(msg, sock, user, token, &last_activity, ip, port);

            // Shift remaining bytes in buffer
            int total_processed = header_len + len;
            memmove(buffer, buffer + total_processed, offset - total_processed);
            offset -= total_processed;
            buffer[offset] = '\0';
        }
    }

    close(sock);
}

// ---------------- MAIN SERVER LOOP ----------------
int main() {
    srand(time(NULL));

    // Zombie process reaper
    signal(SIGCHLD, sigchld_handler);

    // Create database directory if it does not exist
    mkdir(DATA_DIR, 0755);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(server);
        exit(EXIT_FAILURE);
    }

    if (listen(server, 10) < 0) {
        perror("Listen failed");
        close(server);
        exit(EXIT_FAILURE);
    }

    // Professional Startup Banner
    printf(COLOR_GREEN COLOR_BOLD "====================================================\n");
    printf("   🔒 Secure Multiprocessor TCP Application Server  \n");
    printf("====================================================\n" COLOR_RESET);
    printf("  " COLOR_BOLD "Course:" COLOR_RESET "     IE2102 Network Programming\n");
    printf("  " COLOR_BOLD "Student:" COLOR_RESET "    " REGNO "\n");
    printf("  " COLOR_BOLD "Port:" COLOR_RESET "       %d\n", PORT);
    printf("  " COLOR_BOLD "SID:" COLOR_RESET "        %s\n", SID);
    printf("  " COLOR_BOLD "Master PID:" COLOR_RESET " %d\n", getpid());
    printf(COLOR_GREEN "====================================================\n" COLOR_RESET);
    printf("Server listening for incoming connections...\n\n");
    fflush(stdout);

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);

        int client_sock = accept(server, (struct sockaddr*)&client, &len);
        if (client_sock < 0) {
            if (errno == EINTR) continue; // Interrupted by SIGCHLD
            perror("Accept failed");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
        int port = ntohs(client.sin_port);

        pid_t pid = fork();
        if (pid == 0) {
            // Child worker process
            close(server);
            handle_client(client_sock, ip, port);
            exit(0);
        } else if (pid > 0) {
            // Parent listener process
            close(client_sock);
        } else {
            perror("Fork failed");
            close(client_sock);
        }
    }

    close(server);
    return 0;
}
