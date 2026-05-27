#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/wait.h>

/* Compiler-resistant memory zeroing — prevents dead-store elimination */
static void safe_zero(void *s, size_t n) {
    volatile unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = 0;
}

static char passphrase_buf[256];

/* Read passphrase from /dev/tty with echo disabled — replaces deprecated getpass() */
static char *read_passphrase(const char *prompt) {
    int fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    int close_fd = (fd >= 0);
    if (fd < 0) fd = STDERR_FILENO;

    if (write(fd, prompt, strlen(prompt)) < 0) {}

    struct termios old_t, new_t;
    if (tcgetattr(fd, &old_t) < 0) {
        if (close_fd) close(fd);
        return NULL;
    }
    new_t = old_t;
    new_t.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(fd, TCSAFLUSH, &new_t);

    size_t total = 0;
    while (total < sizeof(passphrase_buf) - 1) {
        char c;
        if (read(fd, &c, 1) <= 0 || c == '\n' || c == '\r') break;
        passphrase_buf[total++] = c;
    }
    passphrase_buf[total] = '\0';

    tcsetattr(fd, TCSAFLUSH, &old_t);
    if (write(fd, "\n", 1) < 0) {}
    if (close_fd) close(fd);

    return (total == 0) ? NULL : passphrase_buf;
}

/* Verify passphrase against SSH key using fork+exec — no shell, no command string */
static int verify_passphrase(const char *passphrase, const char *key_path) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        /* passphrase still in argv — visible in /proc/<pid>/cmdline briefly,
           but no shell injection possible and process is short-lived */
        execlp("ssh-keygen", "ssh-keygen", "-y", "-P", passphrase, "-f", key_path, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}

/* Start ssh-agent, parse its output, return SSH_AUTH_SOCK and SSH_AGENT_PID */
static int start_ssh_agent(char *sock_buf, size_t sock_sz, char *pid_buf, size_t pid_sz) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }

    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execlp("ssh-agent", "ssh-agent", "-s", (char *)NULL);
        _exit(127);
    }

    close(pfd[1]);
    char buf[512] = {0};
    ssize_t n = read(pfd[0], buf, sizeof(buf) - 1);
    close(pfd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (n <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;

    /* Parse: SSH_AUTH_SOCK=/tmp/.../agent.NNN; export SSH_AUTH_SOCK; */
    char *sock = strstr(buf, "SSH_AUTH_SOCK=");
    char *apid = strstr(buf, "SSH_AGENT_PID=");
    if (!sock || !apid) return -1;

    sock += strlen("SSH_AUTH_SOCK=");
    char *sock_end = strchr(sock, ';');
    if (!sock_end || (size_t)(sock_end - sock) >= sock_sz) return -1;
    memcpy(sock_buf, sock, (size_t)(sock_end - sock));
    sock_buf[sock_end - sock] = '\0';

    apid += strlen("SSH_AGENT_PID=");
    char *pid_end = strchr(apid, ';');
    if (!pid_end || (size_t)(pid_end - apid) >= pid_sz) return -1;
    memcpy(pid_buf, apid, (size_t)(pid_end - apid));
    pid_buf[pid_end - apid] = '\0';

    /* Validate PID is numeric — guards against malformed ssh-agent output */
    for (size_t i = 0; pid_buf[i]; i++) {
        if (pid_buf[i] < '0' || pid_buf[i] > '9') return -1;
    }

    return 0;
}

/* Add SSH key via expect with passphrase in env — not in cmdline or Tcl script text */
static int add_ssh_key(const char *sock_path, const char *key_path, const char *passphrase) {
    /* Escape key_path for Tcl double-quoted string */
    char escaped_key[512] = {0};
    size_t j = 0;
    for (size_t i = 0; key_path[i] && j < sizeof(escaped_key) - 2; i++) {
        char c = key_path[i];
        if (c == '"' || c == '\\' || c == '[' || c == ']' || c == '$' || c == '{' || c == '}')
            escaped_key[j++] = '\\';
        escaped_key[j++] = c;
    }

    char script[1024];
    int r = snprintf(script, sizeof(script),
        "set timeout 10\n"
        "spawn ssh-add \"%s\"\n"
        "expect \"Enter passphrase\"\n"
        "send \"$env(GIT_ENV_PASS)\\r\"\n"
        "expect eof\n",
        escaped_key);
    if (r < 0 || (size_t)r >= sizeof(script)) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Passphrase lives only in child env, never in Tcl script text or cmdline */
        setenv("GIT_ENV_PASS", passphrase, 1);
        setenv("SSH_AUTH_SOCK", sock_path, 1);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("expect", "expect", "-c", script, (char *)NULL);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}

/* Emit value inside shell single-quoted string, escaping embedded single quotes */
static void print_sq_inner(const char *s) {
    while (*s) {
        if (*s == '\'') fputs("'\\''", stdout);
        else putchar(*s);
        s++;
    }
}

static void print_sq(const char *s) {
    putchar('\'');
    print_sq_inner(s);
    putchar('\'');
}

int main(void) {
    const char *username     = HARDCODED_USER;
    const char *full_name    = HARDCODED_NAME;
    const char *email        = HARDCODED_EMAIL;
    const char *ssh_key_path = HARDCODED_KEY_PATH;

    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "   Unlocking Git Workspace: %s\n", username);
    fprintf(stderr, "=========================================\n");

    char *passphrase = read_passphrase("Enter Environment Unlock Passphrase: ");
    if (passphrase == NULL) {
        fprintf(stderr, "Error: Passphrase cannot be empty.\n");
        return 1;
    }

    if (verify_passphrase(passphrase, ssh_key_path) != 0) {
        fprintf(stderr, "Access Denied: Invalid Passphrase.\n");
        safe_zero(passphrase_buf, sizeof(passphrase_buf));
        return 1;
    }

    fprintf(stderr, "Passphrase verified. Injecting environment context...\n");

    char sock_path[256] = {0};
    char agent_pid[32]  = {0};

    if (start_ssh_agent(sock_path, sizeof(sock_path), agent_pid, sizeof(agent_pid)) != 0) {
        fprintf(stderr, "Warning: Failed to start ssh-agent. SSH key not loaded.\n");
        sock_path[0] = '\0';
    } else if (add_ssh_key(sock_path, ssh_key_path, passphrase) != 0) {
        fprintf(stderr, "Warning: ssh-add failed. Key not loaded into agent.\n");
    }

    /* Zero passphrase immediately after last use — before any stdout output */
    safe_zero(passphrase_buf, sizeof(passphrase_buf));

    /* Emit shell exports — passphrase is gone, no secrets in output */
    printf("export HISTCONTROL=ignorespace;\n");
    printf("export GIT_AUTHOR_NAME=");     print_sq(full_name); printf(";\n");
    printf("export GIT_AUTHOR_EMAIL=");    print_sq(email);     printf(";\n");
    printf("export GIT_COMMITTER_NAME=");  print_sq(full_name); printf(";\n");
    printf("export GIT_COMMITTER_EMAIL="); print_sq(email);     printf(";\n");

    if (sock_path[0]) {
        printf("export SSH_AUTH_SOCK=");        print_sq(sock_path); printf(";\n");
        printf("export SSH_AGENT_PID=%s;\n",    agent_pid);
        printf("export GIT_SSH_AGENT_PID=%s;\n", agent_pid);
    }

    printf("if [ -z \"$OLD_PS1\" ]; then export OLD_PS1=\"$PS1\"; fi;\n");
    printf("export PS1='(git:");
    print_sq_inner(username);
    printf(") '$PS1;\n");

    printf("deactivate_git() {\n"
           "  if [ -n \"$GIT_SSH_AGENT_PID\" ]; then kill \"$GIT_SSH_AGENT_PID\" > /dev/null 2>&1; fi;\n"
           "  unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL;\n"
           "  unset GIT_SSH_AGENT_PID SSH_AUTH_SOCK SSH_AGENT_PID;\n"
           "  export PS1=\"$OLD_PS1\";\n"
           "  unset OLD_PS1;\n"
           "  trap - EXIT;\n"
           "  unset -f deactivate_git;\n"
           "  echo 'Git environment deactivated.';\n"
           "};\n");
    printf("trap deactivate_git EXIT;\n");

    printf("echo 'Workspace loaded. Type \"deactivate_git\" to close.';\n");

    return 0;
}
