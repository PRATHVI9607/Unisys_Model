#!/bin/bash
# Build script for Health Agent Docker image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-health-agent}"
IMAGE_TAG="${IMAGE_TAG:-v3.0}"
REGISTRY="${REGISTRY:-}"

# Construct full image name
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE_NAME="$IMAGE_NAME:$IMAGE_TAG"
fi

echo "Building Health Agent Docker image..."
echo "Project root: $PROJECT_ROOT"
echo "Image name: $FULL_IMAGE_NAME"

# Build the image
docker build \
    -t "$FULL_IMAGE_NAME" \
    -f "$SCRIPT_DIR/Dockerfile" \
    "$PROJECT_ROOT"

echo "✓ Docker image built successfully: $FULL_IMAGE_NAME"

# Show image info
echo ""
echo "Image details:"
docker images "$IMAGE_NAME:$IMAGE_TAG" | head -2

# Optional: Tag as latest
if [ "${TAG_LATEST:-false}" = "true" ]; then
    LATEST_NAME="$IMAGE_NAME:latest"
    if [ -n "$REGISTRY" ]; then
        LATEST_NAME="$REGISTRY/$IMAGE_NAME:latest"
    fi
    docker tag "$FULL_IMAGE_NAME" "$LATEST_NAME"
    echo "✓ Tagged as latest: $LATEST_NAME"
fi

# Optional: Push to registry
if [ -n "$REGISTRY" ] && [ "${PUSH_REGISTRY:-false}" = "true" ]; then
    echo ""
    echo "Pushing image to registry..."
    docker push "$FULL_IMAGE_NAME"
    if [ "${TAG_LATEST:-false}" = "true" ]; then
        docker push "$LATEST_NAME"
    fi
    echo "✓ Image pushed to registry: $REGISTRY"
fi
