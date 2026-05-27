### GIT-ENV

Inject per-user Git identity (name, email, SSH key) into shell env without touching global git config. Each identity compiled into a locked binary.

---

## Dependencies

**Install `expect`** (required for SSH key passphrase automation):
```bash
sudo apt install expect
```

**Disable global Git identity** (prevents global config from overriding injected env vars):
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
bash compile_user.sh
```

Follow prompts — enter username, full name, email. Script generates:
- `~/.git_envs/git_loader_<username>` — locked binary
- `~/.git_envs/activate_<username>.sh` — sourcing wrapper
- `~/.ssh/id_ed25519_<username>` — SSH keypair (if not exists)

Copy printed public key to your Git host (GitHub/GitLab → SSH Keys).

---

## Activate Workspace

Source the generated script (no more `eval`):
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

## Uninstall

Remove a specific user profile:
```bash
bash uninstall.sh <username>
```

Remove all profiles:
```bash
bash uninstall.sh --all
```
