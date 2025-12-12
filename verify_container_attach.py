import docker
import time
from strix.runtime.deployment_manager import TargetDeploymentManager

def verify():
    client = docker.from_env()
    
    # 1. Start a dummy container
    container_name = "strix-test-redis"
    try:
        old = client.containers.get(container_name)
        old.remove(force=True)
    except:
        pass
        
    print(f"Starting {container_name}...")
    container = client.containers.run("redis:alpine", detach=True, name=container_name)
    time.sleep(2) # Wait for startup
    
    try:
        # 2. Initialize Manager and Attach
        print("Initializing DeploymentManager...")
        dm = TargetDeploymentManager()
        
        print(f"Attaching {container_name}...")
        dm.attach_container(container_name)
        
        # 3. Verify List Services
        services = dm.list_services()
        print("Services:", services)
        found = any(s["name"] == container_name for s in services)
        if not found:
            raise Exception("Container not found in services list")
            
        # 4. Verify Execute Command
        print("Executing command...")
        res = dm.execute_command(container_name, "echo hello")
        print("Result:", res)
        if "hello" not in res["stdout"]:
             raise Exception("Command execution failed")
             
        # 5. Verify Get Logs
        print("Getting logs...")
        logs = dm.get_logs(container_name) # Passing container name as service_name
        print("Logs keys:", logs.keys())
        if f"external ({container_name})" not in logs:
             raise Exception("Logs not found")
             
        print("Verification SUCCESS!")
        
    finally:
        print("Cleaning up...")
        container.remove(force=True)

if __name__ == "__main__":
    verify()
