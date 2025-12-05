#!/usr/bin/env python3
"""
Test script to verify the deployment manager fix
"""
import sys
from pathlib import Path

# Add the strix module to the path
sys.path.insert(0, str(Path(__file__).parent))

from strix.runtime.deployment_manager import TargetDeploymentManager

def test_deployment():
    """Test the deployment with the fixed health check logic"""
    print("Testing deployment manager with port 8081...")
    
    compose_file = "/Users/yeyuchen002/Downloads/react19/React-Next-Admin/docker-compose.yml"
    
    try:
        manager = TargetDeploymentManager()
        print(f"✓ Created deployment manager")
        
        print(f"📦 Deploying from: {compose_file}")
        manager.deploy(compose_file)
        print(f"✓ Deployment successful")
        
        print(f"⏳ Waiting for containers to be ready (timeout: 120s)...")
        manager.wait_for_ready(timeout=120)
        print(f"✓ Containers are ready!")
        
        # List services
        services = manager.list_services()
        print(f"\n📊 Deployed services:")
        for svc in services:
            print(f"  - {svc['name']} ({svc['service']})")
            print(f"    Status: {svc['status']}")
            print(f"    IP: {svc['ip']}")
            print(f"    Ports: {svc['ports']}")
        
        print("\n✅ Test completed successfully!")
        print("\nCleaning up...")
        manager.teardown()
        print("✓ Cleanup complete")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_deployment()
