#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void clear_string(char *str) {
    if (str != NULL) {
        while (*str) {
            *str = '\0';
            str++;
        }
    }
}

int main() {
    const char *username = HARDCODED_USER;
    const char *full_name = HARDCODED_NAME;
    const char *email = HARDCODED_EMAIL;
    const char *ssh_key_path = HARDCODED_KEY_PATH;

    fprintf(stderr, "=========================================\n");
    fprintf(stderr, "   Unlocking Git Workspace: %s\n", username);
    fprintf(stderr, "=========================================\n");
    
    char *passphrase = getpass("Enter Environment Unlock Passphrase: ");
    if (passphrase == NULL || strlen(passphrase) == 0) {
        fprintf(stderr, "❌ Error: Passphrase cannot be empty.\n");
        return 1;
    }

    char check_cmd[1024];
    snprintf(check_cmd, sizeof(check_cmd), "ssh-keygen -y -P '%s' -f %s > /dev/null 2>&1", passphrase, ssh_key_path);
    
    if (system(check_cmd) != 0) {
        fprintf(stderr, "❌ Access Denied: Invalid Passphrase.\n");
        clear_string(passphrase);
        clear_string(check_cmd);
        return 1;
    }

    fprintf(stderr, "🔓 Passphrase verified. Injecting environment context...\n");

    printf("export HISTCONTROL=ignorespace;\n");
    printf("export GIT_AUTHOR_NAME='%s';\n", full_name);
    printf("export GIT_AUTHOR_EMAIL='%s';\n", email);
    printf("export GIT_COMMITTER_NAME='%s';\n", full_name);
    printf("export GIT_COMMITTER_EMAIL='%s';\n", email);

    printf("eval \"$(ssh-agent -s)\" > /dev/null;\n");
    printf("export GIT_SSH_AGENT_PID=\"$SSH_AGENT_PID\";\n");

    // FIX: Encapsulated the key path inside escaped double-quotes (\") so expect reads it safely
    printf("expect -c '\n"
           "spawn ssh-add \"%s\"\n"
           "expect \"Enter passphrase\"\n"
           "send \"%s\\r\"\n"
           "expect eof\n"
           "' > /dev/null 2>&1;\n", ssh_key_path, passphrase);

    printf("if [ -z \"$OLD_PS1\" ]; then export OLD_PS1=\"$PS1\"; fi;\n");
    printf("export PS1='(git:%s) '$PS1;\n", username);

    printf("deactivate_git() {\n"
           "  if [ -n \"$GIT_SSH_AGENT_PID\" ]; then kill \"$GIT_SSH_AGENT_PID\" > /dev/null 2>&1; fi;\n"
           "  unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_SSH_AGENT_PID SSH_AUTH_SOCK SSH_AGENT_PID;\n"
           "  export PS1=\"$OLD_PS1\";\n"
           "  unset OLD_PS1;\n"
           "  unset -f deactivate_git;\n"
           "  echo \"Memory footprint wiped. Git environment deactivated successfully.\";\n"
           "};\n");

    printf("echo '🚀 Workspace successfully loaded! Type \"deactivate_git\" to close.';\n");

    clear_string(passphrase);
    clear_string(check_cmd);

    return 0;
}
