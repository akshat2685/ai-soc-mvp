# Install Istio into the cluster
echo "Installing Istio Service Mesh..."
.\istio-1.22.1\bin\istioctl.exe install -y

# Apply PeerAuthentication for strict mTLS (Phase 7 requirement)
echo "apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: STRICT" > k8s/mtls.yaml
kubectl apply -f k8s/mtls.yaml

# Enable Istio sidecar injection
kubectl label namespace default istio-injection=enabled --overwrite

# Apply all microservices
echo "Deploying EDYSOR stack to Kubernetes..."
kubectl apply -f k8s/

echo "Waiting for backend to become ready..."
kubectl rollout status deployment/soc-backend --timeout=120s

echo "Starting EDYSOR Master Test Orchestrator..."
# Port-forward to allow the test orchestrator to hit the cluster
Start-Job -ScriptBlock { kubectl port-forward service/soc-backend 8000:8000 }
Start-Sleep -Seconds 5

# Run the master tests
python backend/tests/edysor_orchestrator/run_tests.py --url http://localhost:8000

echo "Testing complete."
