#!/bin/bash
set -e

# Build script for health-agent:v3-ditsec-embedded Docker image
# This builds the image with the DIT-Sec checkpoint embedded

echo "==== Building health-agent:v3-ditsec-embedded Docker image ===="
echo ""

PROJECT_ROOT="/home/ryan/Desktop/Unisys_Model"
DOCKERFILE="/tmp/dit-sec-testing/Dockerfile.ditsec-embedded"
IMAGE_NAME="health-agent"
IMAGE_TAG="v3-ditsec-embedded"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

echo "Project root: $PROJECT_ROOT"
echo "Dockerfile: $DOCKERFILE"
echo "Image: $FULL_IMAGE"
echo ""

# Verify model checkpoint exists
if [ ! -f "$PROJECT_ROOT/models/dit_sec_v3/dit_sec_v3_checkpoint.pth" ]; then
    echo "ERROR: Model checkpoint not found at $PROJECT_ROOT/models/dit_sec_v3/dit_sec_v3_checkpoint.pth"
    exit 1
fi

echo "✓ Model checkpoint found"

# Verify agent source exists
if [ ! -f "$PROJECT_ROOT/agents/health_agent/main.py" ]; then
    echo "ERROR: Health Agent main.py not found"
    exit 1
fi

echo "✓ Health Agent source found"

# Build the image
echo ""
echo "Building Docker image... this may take 2-3 minutes"
echo ""

cd "$PROJECT_ROOT"

docker build \
    -f "$DOCKERFILE" \
    -t "$FULL_IMAGE" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    .

echo ""
echo "==== Build complete ===="
echo ""
docker images | grep "$IMAGE_NAME" | grep "$IMAGE_TAG"
echo ""
echo "Image is ready: $FULL_IMAGE"
