# Build the Backend
docker build -t edysor-backend:latest ./backend

# Build the Frontend
docker build -t edysor-frontend:latest ./frontend

# Load into Kind cluster
kind load docker-image edysor-backend:latest --name edysor-test-cluster
kind load docker-image edysor-frontend:latest --name edysor-test-cluster

echo "Images built and loaded into the Kubernetes cluster."
