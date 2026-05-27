### GIT-ENV

Inject per-user Git identity (name, email, SSH key) into shell env without touching global git config. Each identity stored as an AES-256-GCM encrypted profile — decrypted only with your SSH key passphrase.

---

## Dependencies

**Python 3** (3.8+) — pre-installed on all modern Linux:
```bash
python3 --version
```

**python3-venv** — needed if `cryptography` package is not installed:
```bash
sudo apt install python3-venv
```

> If `cryptography` is missing, setup automatically creates a virtualenv at
> `~/.git_envs/.venv` and installs it there. No manual pip step needed.

**Disable global Git identity** (prevents global config overriding injected env vars):
```bash
git config --global --unset user.name
git config --global --unset user.email
```

Verify cleared:
```bash
git config --global --list | grep user
```

---

## Setup

```bash
git clone <repo>
cd git-env
python3 setup_user.py
```

Follow prompts — enter username, full name, email, SSH passphrase. Script generates:
- `~/.git_envs/profile_<username>.enc` — AES-256-GCM encrypted identity profile
- `~/.git_envs/unlock.py` — runtime decryptor (copied from repo, self-contained)
- `~/.git_envs/activate_<username>.sh` — sourcing wrapper
- `~/.ssh/id_ed25519_<username>` — SSH keypair (if not exists)

Copy printed public key to your Git host (GitHub/GitLab → SSH Keys).

---

## Activate Workspace

```bash
source ~/.git_envs/activate_<username>.sh
```

Or with dot shorthand:
```bash
. ~/.git_envs/activate_<username>.sh
```

Deactivate when done:
```bash
deactivate_git
```

---

## Security

Profile encrypted with **AES-256-GCM** using a key derived from your SSH passphrase via **PBKDF2-HMAC-SHA256** (600,000 iterations, random salt). Without the passphrase:

- `strings profile.enc` — shows nothing readable
- Brute-force: 600k PBKDF2 iterations per attempt, infeasible
- Tampered file: GCM auth tag fails, immediate rejection

The passphrase never leaves your machine and is not stored anywhere.

---

## Uninstall

Remove a specific user profile:
```bash
bash uninstall.sh <username>
```

Remove all profiles:
```bash
bash uninstall.sh --all
```
