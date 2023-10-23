import uuid
from kubernetes import client, config, watch
from kubernetes.config import ConfigException
import time

try:
    # Try to load the in-cluster configuration. This works if you're running inside Kubernetes.
    config.load_incluster_config()
except ConfigException:
    # If the in-cluster config doesn't load, try the kubeconfig method.
    try:
        config.load_kube_config()
    except ConfigException:
        print(
            "Could not configure Kubernetes client. This script must be run within a cluster or with access to a valid kubeconfig file."
        )
        exit(1)

# Create instances of the API classes
api_instance = client.CoreV1Api()
api_instance_rbac = client.RbacAuthorizationV1Api()
api_instance_apps = client.AppsV1Api()


def sanitize_username(username):
    # Remove or replace invalid characters here, and return a 'safe' version of the username
    sanitized = "".join(e for e in username if e.isalnum())
    return sanitized


def create_service_account(user_id):
    namespace = "dataaccessmanager"
    sanitized_user_id = sanitize_username(user_id)
    name = f"vscode-sa-{sanitized_user_id}"

    # Define the service account with the IRSA role annotation
    body = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(
            name=name,
            annotations={
                # Replace with your actual ARN for the IAM role
                "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/role-name"
            },
        )
    )

    # Create the service account in the specified namespace
    api_instance.create_namespaced_service_account(namespace, body)


def deploy_vscode_server(user_id):
    namespace = "dataaccessmanager"
    sanitized_user_id = sanitize_username(user_id)
    name = f"vscode-server-{sanitized_user_id}"
    service_account_name = f"vscode-sa-{sanitized_user_id}"

    # Define the pod spec with the associated service account
    pod_spec = client.V1PodSpec(
        service_account_name=service_account_name,
        containers=[
            client.V1Container(
                name="vscode-server",
                image="codercom/code-server:latest",
                ports=[client.V1ContainerPort(container_port=8080)],
            )
        ],
    )

    # Define the pod's metadata
    metadata = client.V1ObjectMeta(name=name, labels={"app": name})

    # Create the pod specification
    pod = client.V1Pod(api_version="v1", kind="Pod", metadata=metadata, spec=pod_spec)

    # Deploy the pod in Kubernetes
    api_instance.create_namespaced_pod(namespace, pod)


def create_service_for_vscode(user_id):
    namespace = "dataaccessmanager"
    sanitized_user_id = sanitize_username(user_id)
    name = f"vscode-service-{sanitized_user_id}"

    # Define the service's spec
    spec = client.V1ServiceSpec(
        selector={"app": f"vscode-server-{sanitized_user_id}"},
        ports=[client.V1ServicePort(protocol="TCP", port=80, target_port=8080)],
        type="ClusterIP",
    )

    # Create the service specification
    service = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(name=name),
        spec=spec,
    )

    # Create the service in Kubernetes
    api_instance.create_namespaced_service(namespace, service)


def wait_for_pod_ready(namespace, pod_name):
    # Create a watch object for Pod events
    w = watch.Watch()

    for event in w.stream(api_instance.list_namespaced_pod, namespace):
        pod = event["object"]
        if pod.metadata.name == pod_name and pod.status.phase == "Running":
            w.stop()
            return True  # Pod is now running
        elif pod.metadata.name == pod_name and pod.status.phase == "Failed":
            w.stop()
            return False  # Pod failed to start

    return False  # Default case, though your logic might differ based on how you want to handle timeouts


def launch_vscode_for_user(user_id):
    # Step 1: Create a service account for the user
    create_service_account(user_id)

    # Step 2: Deploy a new VS Code server instance for the user
    deploy_vscode_server(user_id)

    # Step 3: Create a service that targets the new VS Code server
    create_service_for_vscode(user_id)

    # Step 4: Wait for the pod to be in the 'Running' state
    sanitized_user_id = sanitize_username(user_id)
    pod_name = f"vscode-server-{sanitized_user_id}"
    namespace = "dataaccessmanager"

    if wait_for_pod_ready(namespace, pod_name):
        print("VS Code server is ready for use.")
    else:
        print("There was a problem starting the VS Code server.")

    # Here, you might want to return some information about the service, like its ClusterIP
    # to be used for accessing the VS Code instance from within the cluster.
