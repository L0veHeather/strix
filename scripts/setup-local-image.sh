#!/bin/bash
# =============================================================================
# Strix Local Image Setup Script
# =============================================================================
# This script pulls the strix-sandbox image once and tags it locally.
# After running this, Strix will use the local image without external pulls.
#
# Usage:
#   ./scripts/setup-local-image.sh [--save-tar]
#
# Options:
#   --save-tar    Also save the image as a tar file for offline deployment
# =============================================================================

set -e

REMOTE_IMAGE="ghcr.io/usestrix/strix-sandbox:0.1.10"
LOCAL_TAG="strix-sandbox:local"
TAR_FILE="strix-sandbox-0.1.10.tar"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║          Strix Local Image Setup                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if remote image exists locally
if docker image inspect "$REMOTE_IMAGE" > /dev/null 2>&1; then
    echo "✅ Remote image already exists locally: $REMOTE_IMAGE"
else
    echo "📥 Pulling image: $REMOTE_IMAGE"
    echo "   This may take a few minutes..."
    docker pull "$REMOTE_IMAGE"
    echo "✅ Image pulled successfully"
fi

# Tag locally
echo ""
echo "🏷️  Tagging as local: $LOCAL_TAG"
docker tag "$REMOTE_IMAGE" "$LOCAL_TAG"
echo "✅ Local tag created"

# Optionally save as tar
if [[ "$1" == "--save-tar" ]]; then
    echo ""
    echo "💾 Saving image to tar file: $TAR_FILE"
    echo "   This may take a while for large images..."
    docker save -o "$TAR_FILE" "$LOCAL_TAG"
    echo "✅ Tar file created: $TAR_FILE"
    echo ""
    echo "To load on another machine:"
    echo "   docker load -i $TAR_FILE"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ Setup complete!"
echo ""
echo "The local image is ready: $LOCAL_TAG"
echo ""
echo "To use it, either:"
echo "  1. Set environment variable: export STRIX_IMAGE=$LOCAL_TAG"
echo "  2. Or add to .env file: STRIX_IMAGE=$LOCAL_TAG"
echo ""
echo "Strix will now work offline without pulling from ghcr.io"
echo "════════════════════════════════════════════════════════════"
