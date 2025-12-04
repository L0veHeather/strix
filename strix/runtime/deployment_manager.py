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
                
        return logs

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
        return services
