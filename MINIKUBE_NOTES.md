Minikube dev deployment notes

This project includes Kubernetes manifests in `k8s/` to deploy the app, ClamAV, and MinIO into a Minikube cluster for local development.

Prereqs

- minikube installed and running
- kubectl configured to use the minikube context
- Docker (or use minikube's docker-env)

Quick steps

1. Start minikube (if not already):

    minikube start --driver=docker

2. (Optional) Use the minikube docker daemon so images you build locally are available to the cluster:

    eval "$(minikube -p minikube docker-env)"

3. Build the web image locally (tag used in `k8s/web-deployment.yaml`):

    docker build -t sfs:dev .

4. Apply the manifests:

    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/secret.yaml
    kubectl apply -f k8s/minio-deployment.yaml
    kubectl apply -f k8s/clamav-deployment.yaml
    kubectl apply -f k8s/web-deployment.yaml

5. Port-forward to access the services (or use minikube service):

    kubectl -n sfs-dev port-forward svc/sfs-web 5000:5000

    # MinIO console
    kubectl -n sfs-dev port-forward svc/minio 9001:9001

Notes

- These manifests are for development only. They use hostPath volumes and plaintext secrets. Do not use in production.
- The app image is expected to be tagged `sfs:dev` in the cluster. You can build inside minikube's Docker env (see step 2) or push to a registry and update the image name.
- The ClamAV container runs a clamd daemon exposing port 3310 which the app will connect to using the service name `clamav.sfs-dev.svc.cluster.local`.

Troubleshooting

- If the web pod keeps restarting, check logs: `kubectl -n sfs-dev logs deploy/sfs-web`.
- If MinIO console is not reachable, confirm the pod is running and the service exists: `kubectl -n sfs-dev get pods,svc`.
