#!/bin/bash
set -e

ENV_DIR="$HOME/.git_envs"

remove_user() {
    local user="$1"
    local binary="$ENV_DIR/git_loader_$user"
    local activate="$ENV_DIR/activate_$user.sh"
    local key="$HOME/.ssh/id_ed25519_$user"
    local removed=0

    if [ -f "$binary" ]; then
        rm -f "$binary"
        echo "Removed: $binary"
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
    for binary in "$ENV_DIR"/git_loader_*; do
        [ -f "$binary" ] || continue
        users+=("${binary##*/git_loader_}")
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
