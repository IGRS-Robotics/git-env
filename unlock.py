#!/usr/bin/env python3
"""
unlock.py — Decrypt Git identity profile and emit shell environment.
Usage (via activate script):  eval "$(python3 unlock.py profile_<user>.enc)"
"""
import sys
import os
import subprocess
import tempfile
import stat
import json
import re
import getpass
import shlex

VENV_DIR    = os.path.expanduser("~/.git_envs/.venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")
PBKDF2_ITER = 600_000


def ensure_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
        return
    except ImportError:
        pass

    if os.path.abspath(sys.executable) == os.path.abspath(VENV_PYTHON):
        print("Error: cryptography missing even inside venv.", file=sys.stderr)
        sys.exit(1)

    print("cryptography not found. Creating venv and installing...", file=sys.stderr)
    os.makedirs(os.path.dirname(VENV_DIR), exist_ok=True)
    if not os.path.exists(VENV_DIR):
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
    subprocess.run(
        [os.path.join(VENV_DIR, "bin", "pip"), "install", "cryptography"],
        check=True,
    )
    os.execv(VENV_PYTHON, [VENV_PYTHON, os.path.abspath(sys.argv[0])] + sys.argv[1:])


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ITER)
    return kdf.derive(passphrase)


def decrypt_profile(key: bytes, data: bytes) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    nonce  = data[:12]
    ct_tag = data[12:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct_tag, None)
    except InvalidTag:
        print("Access Denied: Invalid Passphrase.", file=sys.stderr)
        sys.exit(1)
    return json.loads(plaintext)


def start_ssh_agent() -> tuple[str | None, str | None]:
    result = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True)
    if result.returncode != 0:
        return None, None
    sock = re.search(r"SSH_AUTH_SOCK=([^;]+)", result.stdout)
    pid  = re.search(r"SSH_AGENT_PID=(\d+)",   result.stdout)
    if not sock or not pid:
        return None, None
    return sock.group(1), pid.group(1)


def add_ssh_key(sock_path: str, key_path: str, passphrase: str) -> bool:
    fd, askpass = tempfile.mkstemp(suffix=".sh")
    try:
        with os.fdopen(fd, "w") as f:
            f.write('#!/bin/sh\nprintf "%s" "$GIT_ENV_PASS"\n')
        os.chmod(askpass, stat.S_IRWXU)

        env = os.environ.copy()
        env.update({
            "GIT_ENV_PASS":          passphrase,
            "SSH_AUTH_SOCK":         sock_path,
            "SSH_ASKPASS":           askpass,
            "SSH_ASKPASS_REQUIRE":   "force",   # OpenSSH >= 8.4
            "DISPLAY":               "fake:0",  # fallback for older OpenSSH
        })
        result = subprocess.run(
            ["ssh-add", key_path],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        env["GIT_ENV_PASS"] = "\x00" * len(passphrase)
        return result.returncode == 0
    finally:
        try:
            os.unlink(askpass)
        except OSError:
            pass


def dq_escape(s: str) -> str:
    """Escape for embedding inside a double-quoted shell string."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def emit_shell(config: dict, sock_path: str | None, agent_pid: str | None) -> None:
    username  = config["username"]
    full_name = config["full_name"]
    email     = config["email"]

    print("export HISTCONTROL=ignorespace;")
    print(f"export GIT_AUTHOR_NAME={shlex.quote(full_name)};")
    print(f"export GIT_AUTHOR_EMAIL={shlex.quote(email)};")
    print(f"export GIT_COMMITTER_NAME={shlex.quote(full_name)};")
    print(f"export GIT_COMMITTER_EMAIL={shlex.quote(email)};")

    if sock_path and agent_pid:
        print(f"export SSH_AUTH_SOCK={shlex.quote(sock_path)};")
        print(f"export SSH_AGENT_PID={agent_pid};")
        print(f"export GIT_SSH_AGENT_PID={agent_pid};")

    print('if [ -z "$OLD_PS1" ]; then export OLD_PS1="$PS1"; fi;')
    print(f'export PS1="(git:{dq_escape(username)}) $PS1";')

    # Shell function + EXIT trap — variables expand at call time, not here
    print(
        "deactivate_git() {\n"
        '  if [ -n "$GIT_SSH_AGENT_PID" ]; then kill "$GIT_SSH_AGENT_PID" > /dev/null 2>&1; fi;\n'
        "  unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL;\n"
        "  unset GIT_SSH_AGENT_PID SSH_AUTH_SOCK SSH_AGENT_PID;\n"
        '  export PS1="$OLD_PS1";\n'
        "  unset OLD_PS1;\n"
        "  trap - EXIT;\n"
        "  unset -f deactivate_git;\n"
        "  echo 'Git environment deactivated.';\n"
        "};"
    )
    print("trap deactivate_git EXIT;")
    print('echo \'Workspace loaded. Type "deactivate_git" to close.\';')


def main() -> None:
    ensure_cryptography()

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <profile.enc>", file=sys.stderr)
        sys.exit(1)

    profile_path = sys.argv[1]
    if not os.path.exists(profile_path):
        print(f"Error: Profile not found: {profile_path}", file=sys.stderr)
        sys.exit(1)

    print("=========================================", file=sys.stderr)
    print("   Git Workspace Unlock",                  file=sys.stderr)
    print("=========================================", file=sys.stderr)

    passphrase = getpass.getpass("Enter Environment Unlock Passphrase: ")
    if not passphrase:
        print("Error: Passphrase cannot be empty.", file=sys.stderr)
        sys.exit(1)

    with open(profile_path, "rb") as f:
        raw = f.read()

    if len(raw) < 28:  # 16 salt + 12 nonce minimum
        print("Error: Profile file corrupted.", file=sys.stderr)
        sys.exit(1)

    salt      = raw[:16]
    encrypted = raw[16:]  # nonce(12) + ciphertext + GCM tag(16)

    key    = derive_key(passphrase.encode(), salt)
    config = decrypt_profile(key, encrypted)  # exits on InvalidTag
    key    = b"\x00" * len(key)

    username    = config["username"]
    ssh_key_path = config["ssh_key_path"]

    print(f"   Unlocking Git Workspace: {username}", file=sys.stderr)
    print("Passphrase verified. Injecting environment context...", file=sys.stderr)

    sock_path, agent_pid = start_ssh_agent()
    if sock_path is None:
        print("Warning: Failed to start ssh-agent. SSH key not loaded.", file=sys.stderr)
    else:
        if not add_ssh_key(sock_path, ssh_key_path, passphrase):
            print("Warning: ssh-add failed. Key not loaded into agent.", file=sys.stderr)

    passphrase = "\x00" * len(passphrase)  # best-effort zero before stdout

    emit_shell(config, sock_path, agent_pid)


if __name__ == "__main__":
    main()
