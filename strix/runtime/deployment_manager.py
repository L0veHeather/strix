import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, NotFound
from docker.models.networks import Network

logger = logging.getLogger(__name__)

STRIX_NETWORK_NAME = "strix-network"

class TargetDeploymentManager:
    """
    Manages the deployment of target applications using docker-compose.
    Ensures they are connected to the Strix network for access.
    """

    def __init__(self) -> None:
        try:
            self.client = docker.from_env()
        except DockerException as e:
            logger.exception("Failed to connect to Docker daemon")
            raise RuntimeError("Docker is not available.") from e
        
        self._deployed_compose_files: list[Path] = []
        self._external_containers: list[Any] = []
        self._network: Network | None = None

    def _ensure_network(self) -> Network:
        """Ensure the shared strix-network exists."""
        try:
            network = self.client.networks.get(STRIX_NETWORK_NAME)
            logger.info(f"Found existing network: {STRIX_NETWORK_NAME}")
            self._network = network
            return network
        except NotFound:
            logger.info(f"Creating network: {STRIX_NETWORK_NAME}")
            self._network = self.client.networks.create(
                STRIX_NETWORK_NAME,
                driver="bridge",
                check_duplicate=True
            )
            return self._network

    def deploy(self, compose_path: str | Path) -> None:
        """
        Deploy a target using docker-compose.
        """
        compose_file = Path(compose_path).resolve()
        if not compose_file.exists():
            raise FileNotFoundError(f"Docker compose file not found: {compose_file}")

        self._ensure_network()

        logger.info(f"Deploying target from: {compose_file}")
        
        # We use subprocess to call docker-compose as python-on-whales or libcompose 
        # might add too many dependencies. Standard CLI is safer.
        
        # First, we need to make sure the compose file uses the strix-network
        # Or we can attach containers after creation. 
        # Attaching after creation is easier than modifying the user's compose file.
        
        try:
            cmd = ["docker", "compose", "-f", str(compose_file), "up", "-d", "--build"]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            self._deployed_compose_files.append(compose_file)
            logger.info("Deployment successful")
            
            # Connect containers to strix-network
            self._attach_containers_to_network(compose_file)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Deployment failed: {e.stderr}")
            raise RuntimeError(f"Failed to deploy {compose_file}: {e.stderr}") from e

    def _attach_containers_to_network(self, compose_file: Path) -> None:
        """
        Attach all containers from a compose project to the strix-network.
        """
        project_name = compose_file.parent.name.lower().replace(" ", "")
        # docker compose uses directory name as default project name usually
        # But let's try to find containers by labels if possible, or just list all and check labels
        
        # A more robust way is using 'docker compose ps -q'
        try:
            cmd = ["docker", "compose", "-f", str(compose_file), "ps", "-q"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_ids = result.stdout.strip().splitlines()
            
            if not self._network:
                self._ensure_network()
                
            for cid in container_ids:
                if not cid:
                    continue
                try:
                    container = self.client.containers.get(cid)
                    # Check if already connected
                    if STRIX_NETWORK_NAME not in container.attrs["NetworkSettings"]["Networks"]:
                        logger.info(f"Connecting container {container.name} to {STRIX_NETWORK_NAME}")
                        self._network.connect(container)
                except Exception as e:
                    logger.warning(f"Failed to connect container {cid} to network: {e}")
                    
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to list containers for network attachment: {e}")

    def attach_container(self, container_name_or_id: str) -> None:
        """
        Attach an existing external container to the Strix network.
        """
        try:
            container = self.client.containers.get(container_name_or_id)
            self._ensure_network()
            
            # Check if already connected
            if STRIX_NETWORK_NAME not in container.attrs["NetworkSettings"]["Networks"]:
                logger.info(f"Connecting external container {container.name} to {STRIX_NETWORK_NAME}")
                self._network.connect(container)
                container.reload()
                
            self._external_containers.append(container)
            logger.info(f"Attached external container: {container.name}")
            
        except NotFound:
            # Re-raise so user knows the container ID is wrong
            raise ValueError(f"Container '{container_name_or_id}' not found") from None
        except Exception as e:
            logger.error(f"Failed to attach container {container_name_or_id}: {e}")
            raise RuntimeError(f"Failed to attach container: {e}") from e

    def wait_for_ready(self, timeout: int = 120, check_interval: int = 2) -> None:
        """
        Wait for all deployed containers to be running and healthy.
        
        Args:
            timeout: Maximum time to wait in seconds (default: 120)
            check_interval: Time between checks in seconds (default: 2)
        
        Raises:
            RuntimeError: If containers are not ready within the timeout period
        """
        if not self._deployed_compose_files:
            logger.info("No deployed containers to wait for")
            return
        
        logger.info(f"Waiting for containers to be ready (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            all_ready = True
            container_statuses = []
            
            for compose_file in self._deployed_compose_files:
                try:
                    cmd = ["docker", "compose", "-f", str(compose_file), "ps", "-q"]
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    container_ids = result.stdout.strip().splitlines()
                    
                    for cid in container_ids:
                        if not cid:
                            continue
                        try:
                            container = self.client.containers.get(cid)
                            container.reload()
                            
                            status = container.status
                            health = container.attrs.get("State", {}).get("Health", {}).get("Status", "none")
                            
                            container_statuses.append({
                                "name": container.name,
                                "status": status,
                                "health": health
                            })
                            
                            # Container is ready if:
                            # 1. It's running AND
                            # 2. Either has no healthcheck OR is healthy/starting
                            # Note: "starting" is valid during the healthcheck start_period
                            if status != "running":
                                all_ready = False
                                logger.debug(f"Container {container.name} not running yet (status: {status})")
                            elif health not in ("none", "healthy", "starting"):
                                all_ready = False
                                logger.debug(f"Container {container.name} not healthy yet (health: {health})")
                            else:
                                logger.debug(f"Container {container.name} is ready (status: {status}, health: {health})")
                                
                        except Exception as e:
                            logger.warning(f"Error checking container {cid}: {e}")
                            all_ready = False
                            
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to list containers: {e}")
                    all_ready = False
            
            if all_ready:
                logger.info("All containers are ready")
                # Give containers a bit more time to fully initialize
                time.sleep(2)
                return
            
            time.sleep(check_interval)
        
        # Timeout reached
        status_msg = "\n".join([
            f"  - {c['name']}: status={c['status']}, health={c['health']}"
            for c in container_statuses
        ])
        raise RuntimeError(
            f"Containers not ready within {timeout}s timeout.\n"
            f"Container statuses:\n{status_msg}"
        )

    def teardown(self) -> None:
        """Stop and remove all deployed services."""
        for compose_file in self._deployed_compose_files:
            logger.info(f"Tearing down deployment: {compose_file}")
            try:
                cmd = ["docker", "compose", "-f", str(compose_file), "down", "-v"]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to teardown {compose_file}: {e.stderr}")
        
        self._deployed_compose_files.clear()
        
        # Optional: remove network if we created it? 
        # Better to leave it or handle it carefully as other things might use it.
        # For now, we leave the network.

        # For external containers, we just clear the list and maybe disconnect them if we wanted to be clean,
        # but leaving them connected is usually harmless and potentially useful for user debugging.
        self._external_containers.clear()

    def get_logs(self, service_name: str | None = None, tail: int = 100) -> dict[str, str]:
        """
        Get logs from deployed containers.
        If service_name is provided, returns logs for that service.
        Otherwise returns logs for all deployed containers.
        """
        logs = {}
        
        # Iterate over all deployed compose files
        for compose_file in self._deployed_compose_files:
            try:
                cmd = ["docker", "compose", "-f", str(compose_file), "ps", "-q"]
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                container_ids = result.stdout.strip().splitlines()
                
                for cid in container_ids:
                    if not cid:
                        continue
                    try:
                        container = self.client.containers.get(cid)
                        c_name = container.name
                        
                        # Filter by service name if requested
                        # Docker compose labels: com.docker.compose.service
                        c_service = container.labels.get("com.docker.compose.service", "")
                        
                        if service_name and service_name != c_service and service_name != c_name:
                            continue
                            
                        log_content = container.logs(tail=tail).decode("utf-8", errors="replace")
                        logs[f"{c_service} ({c_name})"] = log_content
                        
                    except Exception as e:
                        logger.warning(f"Failed to get logs for {cid}: {e}")
                        
            except subprocess.CalledProcessError:
                pass
        
        # Add logs from external containers
        for container in self._external_containers:
            try:
                c_name = container.name
                # External containers don't have a specific service name concept, use name
                if service_name and service_name != c_name:
                    continue
                    
                log_content = container.logs(tail=tail).decode("utf-8", errors="replace")
                logs[f"external ({c_name})"] = log_content
            except Exception as e:
                logger.warning(f"Failed to get logs for external container {container.name}: {e}")

        return logs

    def execute_command(self, service_name: str, command: str, user: str | None = None) -> dict[str, Any]:
        """
        Execute a command in a deployed container.
        
        Args:
            service_name: Name of the service/container to execute command in.
            command: Command string to execute.
            user: Optional user to execute command as.
            
        Returns:
            Dict containing exit_code, stdout, and stderr.
        """
        target_cid = None
        target_container = None
        
        # Find the container
        for compose_file in self._deployed_compose_files:
            try:
                cmd = ["docker", "compose", "-f", str(compose_file), "ps", "-q"]
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                container_ids = result.stdout.strip().splitlines()
                
                for cid in container_ids:
                    if not cid:
                        continue
                    try:
                        container = self.client.containers.get(cid)
                        # Check name or service label
                        if (container.name == service_name or 
                            container.labels.get("com.docker.compose.service") == service_name):
                            target_cid = cid
                            target_container = container
                            break
                    except Exception:
                        pass
                if target_cid:
                    break
            except subprocess.CalledProcessError:
                pass
        
        # Check external containers if not found yet
        if not target_container:
            for container in self._external_containers:
                if container.name == service_name or container.short_id == service_name or container.id == service_name:
                    target_container = container
                    break

                
        if not target_container:
            raise ValueError(f"Service or container '{service_name}' not found")
            
        logger.info(f"Executing command in {target_container.name}: {command}")
        
        try:
            # simple exec_run
            exit_code, output = target_container.exec_run(
                command, 
                user=user or "",
                demux=True # Separate stdout/stderr
            )
            
            stdout_bytes, stderr_bytes = output if output else (b"", b"")
            
            return {
                "exit_code": exit_code,
                "stdout": stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else "",
                "stderr": stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            }
            
        except Exception as e:
            logger.error(f"Failed to execute command: {e}")
            raise RuntimeError(f"Command execution failed: {e}") from e

    def list_services(self) -> list[dict[str, Any]]:
        """List all deployed services and their network info."""
        services = []
        for compose_file in self._deployed_compose_files:
            try:
                cmd = ["docker", "compose", "-f", str(compose_file), "ps", "-q"]
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                container_ids = result.stdout.strip().splitlines()
                
                for cid in container_ids:
                    if not cid:
                        continue
                    try:
                        container = self.client.containers.get(cid)
                        
                        networks = container.attrs["NetworkSettings"]["Networks"]
                        ip_address = ""
                        if STRIX_NETWORK_NAME in networks:
                            ip_address = networks[STRIX_NETWORK_NAME]["IPAddress"]
                        
                        services.append({
                            "name": container.name,
                            "service": container.labels.get("com.docker.compose.service", "unknown"),
                            "id": container.short_id,
                            "status": container.status,
                            "ip": ip_address,
                            "ports": container.attrs["NetworkSettings"]["Ports"]
                        })
                    except Exception:
                        pass
            except subprocess.CalledProcessError:
                pass

        # Add external containers
        for container in self._external_containers:
            try:
                container.reload()
                networks = container.attrs["NetworkSettings"]["Networks"]
                ip_address = ""
                if STRIX_NETWORK_NAME in networks:
                    ip_address = networks[STRIX_NETWORK_NAME]["IPAddress"]
                
                services.append({
                    "name": container.name,
                    "service": "external",
                    "id": container.short_id,
                    "status": container.status,
                    "ip": ip_address,
                    "ports": container.attrs["NetworkSettings"]["Ports"]
                })
            except Exception:
                pass

        return services
