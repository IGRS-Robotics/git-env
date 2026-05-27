#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/prctl.h>

/* ── Memory ──────────────────────────────────────────────────────────────── */

static void safe_zero(void *s, size_t n) {
    volatile unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = 0;
}

/* ── SHA-256 (public domain — Brad Conte, brad@bradconte.com) ────────────── */

typedef uint32_t sha_word;

typedef struct {
    unsigned char data[64];
    sha_word      datalen;
    uint64_t      bitlen;
    sha_word      state[8];
} SHA256_CTX;

#define ROTR(a,b) (((a)>>(b))|((a)<<(32-(b))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static const sha_word K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const unsigned char *data) {
    sha_word a,b,c,d,e,f,g,h,t1,t2,m[64];
    sha_word i,j;
    for (i=0,j=0; i<16; ++i,j+=4)
        m[i]=((sha_word)data[j]<<24)|((sha_word)data[j+1]<<16)|((sha_word)data[j+2]<<8)|data[j+3];
    for (; i<64; ++i)
        m[i]=SG1(m[i-2])+m[i-7]+SG0(m[i-15])+m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i=0; i<64; ++i) {
        t1=h+EP1(e)+CH(e,f,g)+K[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t len) {
    for (size_t i=0; i<len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, unsigned char *hash) {
    sha_word i = ctx->datalen;
    if (i < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63]=(unsigned char)(ctx->bitlen);
    ctx->data[62]=(unsigned char)(ctx->bitlen>>8);
    ctx->data[61]=(unsigned char)(ctx->bitlen>>16);
    ctx->data[60]=(unsigned char)(ctx->bitlen>>24);
    ctx->data[59]=(unsigned char)(ctx->bitlen>>32);
    ctx->data[58]=(unsigned char)(ctx->bitlen>>40);
    ctx->data[57]=(unsigned char)(ctx->bitlen>>48);
    ctx->data[56]=(unsigned char)(ctx->bitlen>>56);
    sha256_transform(ctx, ctx->data);
    for (i=0; i<4; ++i) {
        hash[i]    =(ctx->state[0]>>(24-i*8))&0xff;
        hash[i+4]  =(ctx->state[1]>>(24-i*8))&0xff;
        hash[i+8]  =(ctx->state[2]>>(24-i*8))&0xff;
        hash[i+12] =(ctx->state[3]>>(24-i*8))&0xff;
        hash[i+16] =(ctx->state[4]>>(24-i*8))&0xff;
        hash[i+20] =(ctx->state[5]>>(24-i*8))&0xff;
        hash[i+24] =(ctx->state[6]>>(24-i*8))&0xff;
        hash[i+28] =(ctx->state[7]>>(24-i*8))&0xff;
    }
    safe_zero(ctx, sizeof(*ctx));
}

static void sha256_hash(const unsigned char *data, size_t len, unsigned char out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ── Key derivation & decryption ─────────────────────────────────────────── */

static void derive_key(unsigned char key[32], const char *passphrase) {
    sha256_hash((const unsigned char *)passphrase, strlen(passphrase), key);
}

/* Encrypted null sentinel = key[i%32] at null's position → decrypts to 0 */
static void decrypt_str(char *out, size_t out_sz,
                         const unsigned char *enc, const unsigned char key[32]) {
    size_t i = 0;
    while (i < out_sz - 1) {
        unsigned char p = enc[i] ^ key[i % 32];
        if (p == '\0') break;
        out[i++] = (char)p;
    }
    out[i] = '\0';
}

/* ── Passphrase input ────────────────────────────────────────────────────── */

static char passphrase_buf[256];

static char *read_passphrase(const char *prompt) {
    int fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    int close_fd = (fd >= 0);
    if (fd < 0) fd = STDERR_FILENO;

    if (write(fd, prompt, strlen(prompt)) < 0) {}

    struct termios old_t, new_t;
    if (tcgetattr(fd, &old_t) < 0) { if (close_fd) close(fd); return NULL; }
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

/* ── SSH helpers ─────────────────────────────────────────────────────────── */

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
        execlp("ssh-keygen", "ssh-keygen", "-y", "-P", passphrase, "-f", key_path, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}

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

    for (size_t i = 0; pid_buf[i]; i++) {
        if (pid_buf[i] < '0' || pid_buf[i] > '9') return -1;
    }
    return 0;
}

static int add_ssh_key(const char *sock_path, const char *key_path, const char *passphrase) {
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

/* ── Shell output helpers ────────────────────────────────────────────────── */

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

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    prctl(PR_SET_DUMPABLE, 0);

    static const unsigned char enc_username[]     = HARDCODED_USER;
    static const unsigned char enc_full_name[]    = HARDCODED_NAME;
    static const unsigned char enc_email[]        = HARDCODED_EMAIL;
    static const unsigned char enc_ssh_key_path[] = HARDCODED_KEY_PATH;

    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "   Git Workspace Unlock\n");
    fprintf(stderr, "=========================================\n");

    char *passphrase = read_passphrase("Enter Environment Unlock Passphrase: ");
    if (passphrase == NULL) {
        fprintf(stderr, "Error: Passphrase cannot be empty.\n");
        return 1;
    }

    /* Derive decryption key from passphrase — key never stored in binary */
    unsigned char dec_key[32];
    derive_key(dec_key, passphrase);

    /* Decrypt ssh_key_path first — needed to verify passphrase */
    char ssh_key_path[256];
    decrypt_str(ssh_key_path, sizeof(ssh_key_path), enc_ssh_key_path, dec_key);

    /* SSH key verification also validates the decryption: wrong passphrase
       → wrong key → garbage path or garbage passphrase → ssh-keygen fails */
    if (verify_passphrase(passphrase, ssh_key_path) != 0) {
        fprintf(stderr, "Access Denied: Invalid Passphrase.\n");
        safe_zero(dec_key,      sizeof(dec_key));
        safe_zero(ssh_key_path, sizeof(ssh_key_path));
        safe_zero(passphrase_buf, sizeof(passphrase_buf));
        return 1;
    }

    char username[64], full_name[128], email[128];
    decrypt_str(username,  sizeof(username),  enc_username,  dec_key);
    decrypt_str(full_name, sizeof(full_name), enc_full_name, dec_key);
    decrypt_str(email,     sizeof(email),     enc_email,     dec_key);

    safe_zero(dec_key, sizeof(dec_key));

    fprintf(stderr, "   Unlocking Git Workspace: %s\n", username);
    fprintf(stderr, "Passphrase verified. Injecting environment context...\n");

    char sock_path[256] = {0};
    char agent_pid[32]  = {0};

    if (start_ssh_agent(sock_path, sizeof(sock_path), agent_pid, sizeof(agent_pid)) != 0) {
        fprintf(stderr, "Warning: Failed to start ssh-agent. SSH key not loaded.\n");
        sock_path[0] = '\0';
    } else if (add_ssh_key(sock_path, ssh_key_path, passphrase) != 0) {
        fprintf(stderr, "Warning: ssh-add failed. Key not loaded into agent.\n");
    }

    safe_zero(passphrase_buf, sizeof(passphrase_buf));

    printf("export HISTCONTROL=ignorespace;\n");
    printf("export GIT_AUTHOR_NAME=");     print_sq(full_name); printf(";\n");
    printf("export GIT_AUTHOR_EMAIL=");    print_sq(email);     printf(";\n");
    printf("export GIT_COMMITTER_NAME=");  print_sq(full_name); printf(";\n");
    printf("export GIT_COMMITTER_EMAIL="); print_sq(email);     printf(";\n");

    if (sock_path[0]) {
        printf("export SSH_AUTH_SOCK=");         print_sq(sock_path); printf(";\n");
        printf("export SSH_AGENT_PID=%s;\n",     agent_pid);
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

    safe_zero(username,     sizeof(username));
    safe_zero(full_name,    sizeof(full_name));
    safe_zero(email,        sizeof(email));
    safe_zero(ssh_key_path, sizeof(ssh_key_path));

    return 0;
}
