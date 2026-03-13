#!/usr/bin/env bash
# Patch setup.py to use a matching branch of eudi-wallet-it-python when it exists.
# Expects env: CURRENT_BRANCH, TARGET_BRANCH (optional), DEPTH_COMMITS (optional).
# Run from repository root.

set -e

CURRENT_BRANCH="${CURRENT_BRANCH:-master}"
TARGET_BRANCH="${TARGET_BRANCH:-master}"
DEPTH_COMMITS="${DEPTH_COMMITS:-50}"

PYEUDIW_REPO_NAME="eudi-wallet-it-python"
PYEUDIW_REPO_URL="https://github.com/italia/${PYEUDIW_REPO_NAME}"
PYEUDIW_REPO_GIT="${PYEUDIW_REPO_URL}.git"

SETUP_PY_PATH="iam-proxy-italia-project/setup.py"

echo "Current branch: '$CURRENT_BRANCH'"
echo "Target branch: '$TARGET_BRANCH'"
echo "pyeudiw git repo: '$PYEUDIW_REPO_GIT'"
echo "setup.py path: '$SETUP_PY_PATH'"

if [ "$CURRENT_BRANCH" = "master" ]; then
  echo "Current branch is master → no patch needed."
  exit 0
fi

# Guarda o diretório raiz do projeto
PROJECT_ROOT=$(pwd)

# Verifica se o setup.py existe
if [ ! -f "$PROJECT_ROOT/$SETUP_PY_PATH" ]; then
  echo "ERROR: setup.py not found at $PROJECT_ROOT/$SETUP_PY_PATH"
  exit 1
fi

TMP_DIR=$(mktemp -d)
git clone --quiet --no-checkout "$PYEUDIW_REPO_GIT" "$TMP_DIR"
cd "$TMP_DIR"

if git ls-remote --exit-code --heads "$PYEUDIW_REPO_GIT" "$CURRENT_BRANCH" >/dev/null 2>&1; then
  echo "Branch '$CURRENT_BRANCH' exists in '$PYEUDIW_REPO_NAME' → checking if it's merged..."
  git fetch origin "$CURRENT_BRANCH" --depth="$DEPTH_COMMITS" >/dev/null 2>&1 || true
  git fetch origin "$TARGET_BRANCH" --depth="$DEPTH_COMMITS" >/dev/null 2>&1 || true
  git fetch origin master --depth="$DEPTH_COMMITS" >/dev/null 2>&1 || true

  if git merge-base --is-ancestor "origin/$CURRENT_BRANCH" "origin/$TARGET_BRANCH" 2>/dev/null; then
    echo "Branch '$CURRENT_BRANCH' has already been merged into '$TARGET_BRANCH' → will use '$TARGET_BRANCH'."
    CURRENT_BRANCH="$TARGET_BRANCH"
  elif git merge-base --is-ancestor "origin/$CURRENT_BRANCH" "origin/master" 2>/dev/null; then
    echo "Branch '$CURRENT_BRANCH' has already been merged into 'master' → will use 'master'."
    CURRENT_BRANCH="master"
  fi
else
  echo "Branch '$CURRENT_BRANCH' does not exist in '$PYEUDIW_REPO_NAME' → skipping merge check."
fi

cd - >/dev/null
rm -rf "$TMP_DIR"

# Volta para o diretório raiz
cd "$PROJECT_ROOT"

BRANCH_CANDIDATES=()
[ -n "$CURRENT_BRANCH" ] && BRANCH_CANDIDATES+=("$CURRENT_BRANCH")
[ -n "$TARGET_BRANCH" ] && [[ "$TARGET_BRANCH" != "$CURRENT_BRANCH" ]] && BRANCH_CANDIDATES+=("$TARGET_BRANCH")
BRANCH_CANDIDATES+=("master")

# Remove duplicatas
BRANCH_CANDIDATES=($(echo "${BRANCH_CANDIDATES[@]}" | tr ' ' '\n' | awk '!seen[$0]++' | tr '\n' ' '))

echo "Branch candidates for patch: ${BRANCH_CANDIDATES[*]}"

for BRANCH in "${BRANCH_CANDIDATES[@]}"; do
  echo "Checking if branch '$BRANCH' exists in '$PYEUDIW_REPO_NAME'..."
  if git ls-remote --heads "$PYEUDIW_REPO_GIT" "$BRANCH" | grep -q "$BRANCH"; then
    echo "Branch '$BRANCH' found! Patching setup.py..."
    
    # Usa sed para substituir o commit hash pelo nome do branch
    # Isso assume que a linha tem o formato exato com o hash
    sed -i "s|pyeudiw\[satosa\] @ git+${PYEUDIW_REPO_URL}@[a-f0-9]\+|pyeudiw[satosa] @ git+${PYEUDIW_REPO_GIT}@${BRANCH}|g" "$SETUP_PY_PATH"
    
    echo "Patched setup.py to use branch: $BRANCH"
    cat "$SETUP_PY_PATH" | grep "pyeudiw"  # Mostra a linha modificada para debug
    exit 0
  fi
done

echo "No matching branch found. Using default setup.py."