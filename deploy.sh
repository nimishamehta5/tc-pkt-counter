#!/bin/bash
set -e

REGISTRY=""
REPO=""
TAG=""

# Create kind cluster if it doesn't exist
if ! kind get clusters | grep -q "ebpf-cluster"; then
    echo "Creating kind cluster..."
    kind create cluster --config kind-config.yaml
fi

# Build the Docker image
echo "Building Docker image..."
docker build -t localhost/tc-pkt-counter:latest .

# Load the image into kind
echo "Loading image into kind cluster..."
kind load docker-image localhost/tc-pkt-counter:latest --name ebpf-cluster

# optional: if you are using an external registry
# docker tag kind/tc-pkt-counter:latest $REGISTRY/$REPO:$TAG
# docker push $REGISTRY/$REPO:$TAG

# Ensure using the correct context
kubectl config use-context kind-ebpf-cluster

# Apply the Kubernetes manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f k8s/

echo "Deployment complete! Monitor the pods with:"
echo "kubectl get pods -w"
