#!/bin/bash
set -e

echo "========================================="
echo "   Secure Binary Compiler Controller     "
echo "========================================="
echo ""

# 1. Auto-detect ONLY the home directory path safely using system variables
USER_HOME="$HOME"
echo "🤖 Auto-detected Home Path: $USER_HOME"
echo ""

# 2. Gather ALL profile configurations manually
read -p "Target Git Workspace Username (e.g., dev01): " TARGET_USER
TARGET_USER=$(echo "$TARGET_USER" | tr -d ' ')

if [ -z "$TARGET_USER" ]; then
    echo "Error: Username cannot be empty."
    exit 1
fi

read -p "Full Commit Name (e.g., Dev User): " FULL_NAME
read -p "Git Email Address (e.g., dev@domain.local): " EMAIL

# 3. Establish absolute paths inside your auto-detected home (.git_envs)
ENV_DIR="$USER_HOME/.git_envs"
ABS_KEY_PATH="$USER_HOME/.ssh/id_ed25519_$TARGET_USER"
OUTPUT_BINARY="$ENV_DIR/git_loader_$TARGET_USER"

echo ""
echo "-----------------------------------------"
echo "Provisioning directories and compiling..."
echo "-----------------------------------------"

# 4. Initialize environment folders directly inside your user workspace
mkdir -p "$ENV_DIR"
mkdir -p "$USER_HOME/.ssh"

# 5. Guard check for base source code
if [ ! -f "git_env.c" ]; then
    echo "Error: Base file 'git_env.c' not found in current execution directory."
    exit 1
fi

# 6. Check if an SSH key exists for this username, if not, prompt to create it
if [ ! -f "$ABS_KEY_PATH" ]; then
    echo "🔑 No SSH key detected at: $ABS_KEY_PATH"
    echo "Generating a secure password-protected identity key for $TARGET_USER..."
    ssh-keygen -t ed25519 -C "$EMAIL" -f "$ABS_KEY_PATH"
    echo ""
fi

echo "Compiling optimized machine binary..."

# 7. Compile with extreme optimizations and strip debug tags
gcc -s -O3 git_env.c -o "$OUTPUT_BINARY" \
    -DHARDCODED_USER='"'"$TARGET_USER"'"' \
    -DHARDCODED_NAME='"'"$FULL_NAME"'"' \
    -DHARDCODED_EMAIL='"'"$EMAIL"'"' \
    -DHARDCODED_KEY_PATH='"'"$ABS_KEY_PATH"'"'

# 8. Lockdown permissions locally inside the user directory
chmod 700 "$ENV_DIR"
chmod 700 "$OUTPUT_BINARY"

ACTIVATE_SCRIPT="$ENV_DIR/activate_$TARGET_USER.sh"

cat > "$ACTIVATE_SCRIPT" << EOF
#!/bin/bash
eval "\$(${OUTPUT_BINARY})"
EOF
chmod 700 "$ACTIVATE_SCRIPT"

echo ""
echo "========================================="
echo "🎉 Setup Complete for $TARGET_USER!"
echo "========================================="
echo ""
echo "👉 STEP 1: Copy this public key to your Git host settings account:"
echo "------------------------------------------------------------------------"
cat "${ABS_KEY_PATH}.pub"
echo "------------------------------------------------------------------------"
echo ""
echo "👉 STEP 2: Source this to activate your workspace:"
echo "  source $ACTIVATE_SCRIPT"
echo ""
