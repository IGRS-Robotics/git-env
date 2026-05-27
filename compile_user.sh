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

# 7. Prompt for passphrase, verify it, then derive encryption key
echo ""
read -rsp "Enter SSH Key Passphrase (encrypts your profile into the binary): " BUILD_PASSPHRASE
echo ""

if ! ssh-keygen -y -P "$BUILD_PASSPHRASE" -f "$ABS_KEY_PATH" > /dev/null 2>&1; then
    echo "Error: Incorrect passphrase for $ABS_KEY_PATH"
    exit 1
fi

# Derive 32-byte key: SHA-256(passphrase) as 64 hex chars
KEY_HEX=$(printf '%s' "$BUILD_PASSPHRASE" | sha256sum | cut -d' ' -f1)
BUILD_PASSPHRASE=""  # best-effort zero after derivation

# XOR-encrypt string with repeating 32-byte key derived from passphrase.
# Appends encrypted null sentinel (0x00 ^ key[i%32] = key[i%32]) as terminator.
# Requires python3 (handles UTF-8 and avoids bash char-to-int portability issues).
encrypt_str() {
    local str="$1"
    python3 -c "
import sys
s   = sys.argv[1]
key = bytes.fromhex('$KEY_HEX')
enc = s.encode('utf-8')
out = [str(b ^ key[i % 32]) for i, b in enumerate(enc)]
out.append(str(key[len(enc) % 32]))   # encrypted null terminator
print(','.join(out))
" "$str"
}

echo "Encrypting profile strings and compiling..."

# 8. Compile with hardening flags; profile strings embedded as ciphertext only
gcc -s -O3 git_env.c -o "$OUTPUT_BINARY" \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
    -Wl,-z,relro,-z,now \
    -DHARDCODED_USER="{$(encrypt_str "$TARGET_USER")}" \
    -DHARDCODED_NAME="{$(encrypt_str "$FULL_NAME")}" \
    -DHARDCODED_EMAIL="{$(encrypt_str "$EMAIL")}" \
    -DHARDCODED_KEY_PATH="{$(encrypt_str "$ABS_KEY_PATH")}"

# Remove metadata sections that leak build info
strip --strip-all --remove-section=.comment --remove-section=.note "$OUTPUT_BINARY"

# 9. Lockdown permissions locally inside the user directory
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
