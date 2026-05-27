#!/bin/bash
set -e

ENV_DIR="$HOME/.git_envs"

remove_user() {
    local user="$1"
    local profile="$ENV_DIR/profile_$user.enc"
    local activate="$ENV_DIR/activate_$user.sh"
    local key="$HOME/.ssh/id_ed25519_$user"
    local removed=0

    if [ -f "$profile" ]; then
        rm -f "$profile"
        echo "Removed: $profile"
        removed=1
    fi

    if [ -f "$activate" ]; then
        rm -f "$activate"
        echo "Removed: $activate"
        removed=1
    fi

    if [ "$removed" -eq 0 ]; then
        echo "No profile found for user: $user"
        return 1
    fi

    if [ -f "$key" ] || [ -f "${key}.pub" ]; then
        read -p "Remove SSH key for $user? (${key}) [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -f "$key" "${key}.pub"
            echo "Removed SSH key pair for $user"
        fi
    fi

    # If no profiles remain, offer to remove shared files
    local remaining
    remaining=$(find "$ENV_DIR" -maxdepth 1 -name "profile_*.enc" 2>/dev/null | wc -l)
    if [ "$remaining" -eq 0 ]; then
        if [ -f "$ENV_DIR/unlock.py" ]; then
            read -p "No profiles remain. Remove unlock.py? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                rm -f "$ENV_DIR/unlock.py"
                echo "Removed: $ENV_DIR/unlock.py"
            fi
        fi

        if [ -d "$ENV_DIR/.venv" ]; then
            read -p "Remove Python venv ($ENV_DIR/.venv)? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                rm -rf "$ENV_DIR/.venv"
                echo "Removed: $ENV_DIR/.venv"
            fi
        fi
    fi

    if [ -d "$ENV_DIR" ] && [ -z "$(ls -A "$ENV_DIR")" ]; then
        rmdir "$ENV_DIR"
        echo "Removed empty directory: $ENV_DIR"
    fi

    echo "Uninstall complete for: $user"
}

if [ $# -eq 0 ]; then
    echo "Usage: bash uninstall.sh <username>"
    echo "       bash uninstall.sh --all"
    exit 1
fi

if [ "$1" = "--all" ]; then
    if [ ! -d "$ENV_DIR" ]; then
        echo "Nothing to remove — $ENV_DIR does not exist."
        exit 0
    fi

    users=()
    for profile in "$ENV_DIR"/profile_*.enc; do
        [ -f "$profile" ] || continue
        base="${profile##*/profile_}"
        users+=("${base%.enc}")
    done

    if [ ${#users[@]} -eq 0 ]; then
        echo "No profiles found in $ENV_DIR"
        exit 0
    fi

    echo "Found profiles: ${users[*]}"
    read -p "Remove all profiles? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi

    for user in "${users[@]}"; do
        remove_user "$user"
    done
else
    remove_user "$1"
fi
