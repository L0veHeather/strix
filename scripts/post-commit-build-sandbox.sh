#!/bin/bash
# Post-commit hook: Auto-rebuild strix-sandbox image when relevant files change
#
# Installation:
#   cp scripts/post-commit-build-sandbox.sh .git/hooks/post-commit
#   chmod +x .git/hooks/post-commit
#
# Or symlink (recommended for version control):
#   ln -sf ../../scripts/post-commit-build-sandbox.sh .git/hooks/post-commit

set -e

# Files/directories that trigger a rebuild
WATCH_PATHS=(
    "strix/tools/"
    "strix/runtime/"
    "containers/Dockerfile"
    "containers/docker-entrypoint.sh"
    "pyproject.toml"
    "poetry.lock"
)

# Check if any watched files were modified in the last commit
files_changed=$(git diff-tree --no-commit-id --name-only -r HEAD 2>/dev/null || echo "")

should_rebuild=false
for watch_path in "${WATCH_PATHS[@]}"; do
    if echo "$files_changed" | grep -q "^${watch_path}"; then
        should_rebuild=true
        echo "🔍 Detected changes in: $watch_path"
    fi
done

if [ "$should_rebuild" = true ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🐳 Auto-rebuilding strix-sandbox image..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Get project root (where this script's repo is)
    PROJECT_ROOT="$(git rev-parse --show-toplevel)"
    cd "$PROJECT_ROOT"
    
    # Build the image
    if make build-sandbox; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "✅ Sandbox image rebuilt successfully!"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    else
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "⚠️  Sandbox image rebuild failed (commit still succeeded)"
        echo "   Run 'make build-sandbox' manually to debug"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
else
    echo "ℹ️  No sandbox-related changes detected, skipping rebuild"
fi
