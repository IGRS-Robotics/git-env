#!/usr/bin/env python3
"""
setup_user.py — Create an encrypted Git identity profile.
Replaces compile_user.sh. No gcc, no binary, no expect required.
"""
import sys
import os
import subprocess
import shutil
import stat
import json
import getpass

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


def encrypt_config(key: bytes, config: dict) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(config).encode(), None)
    return nonce + ct  # 12-byte nonce + ciphertext + 16-byte GCM tag


def verify_passphrase(passphrase: str, key_path: str) -> bool:
    r = subprocess.run(
        ["ssh-keygen", "-y", "-P", passphrase, "-f", key_path],
        capture_output=True,
    )
    return r.returncode == 0


def main() -> None:
    ensure_cryptography()

    print("=========================================")
    print("   Git Identity Setup")
    print("=========================================\n")

    user_home = os.path.expanduser("~")
    env_dir   = os.path.join(user_home, ".git_envs")
    os.makedirs(env_dir, exist_ok=True)
    os.makedirs(os.path.join(user_home, ".ssh"), exist_ok=True)

    username = input("Target Git Workspace Username (e.g., dev01): ").strip().replace(" ", "")
    if not username:
        print("Error: Username cannot be empty.", file=sys.stderr)
        sys.exit(1)

    full_name = input("Full Commit Name (e.g., Dev User): ").strip()
    email     = input("Git Email Address (e.g., dev@domain.local): ").strip()

    key_path      = os.path.join(user_home, ".ssh", f"id_ed25519_{username}")
    profile_path  = os.path.join(env_dir, f"profile_{username}.enc")
    activate_path = os.path.join(env_dir, f"activate_{username}.sh")
    unlock_dst    = os.path.join(env_dir, "unlock.py")

    if not os.path.exists(key_path):
        print(f"\n🔑 No SSH key at {key_path}. Generating...")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", email, "-f", key_path],
            check=True,
        )

    print()
    passphrase = getpass.getpass("Enter SSH Key Passphrase (encrypts your profile): ")
    if not passphrase:
        print("Error: Passphrase cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if not verify_passphrase(passphrase, key_path):
        print("Error: Incorrect passphrase for key.", file=sys.stderr)
        sys.exit(1)

    print("Passphrase verified. Encrypting profile...")

    config = {
        "username":     username,
        "full_name":    full_name,
        "email":        email,
        "ssh_key_path": key_path,
    }

    salt      = os.urandom(16)
    key       = derive_key(passphrase.encode(), salt)
    encrypted = encrypt_config(key, config)
    key       = b"\x00" * len(key)  # best-effort zero (Python strings are immutable)

    with open(profile_path, "wb") as f:
        f.write(salt + encrypted)
    os.chmod(profile_path, stat.S_IRUSR | stat.S_IWUSR)

    # Copy unlock.py into ~/.git_envs/ so the repo isn't needed at runtime
    script_dir = os.path.dirname(os.path.abspath(__file__))
    shutil.copy2(os.path.join(script_dir, "unlock.py"), unlock_dst)
    os.chmod(unlock_dst, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    activate_content = (
        "#!/bin/bash\n"
        'VENV_PY="$HOME/.git_envs/.venv/bin/python3"\n'
        'PYTHON="python3"\n'
        '[ -f "$VENV_PY" ] && PYTHON="$VENV_PY"\n'
        f'eval "$($PYTHON {unlock_dst} {profile_path})"\n'
    )
    with open(activate_path, "w") as f:
        f.write(activate_content)
    os.chmod(activate_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    os.chmod(env_dir, stat.S_IRWXU)

    print()
    print("=========================================")
    print(f"🎉 Setup Complete for {username}!")
    print("=========================================\n")
    print("👉 STEP 1: Copy this public key to your Git host:")
    print("------------------------------------------------------------------------")
    with open(f"{key_path}.pub") as f:
        print(f.read().strip())
    print("------------------------------------------------------------------------\n")
    print("👉 STEP 2: Source this to activate your workspace:")
    print(f"  source {activate_path}\n")


if __name__ == "__main__":
    main()
