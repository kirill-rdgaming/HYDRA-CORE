"""
Example: Using HYDRA7 as a library in your Python application
"""

import asyncio
import os
from hydra7 import HydraNode


async def main():
    """
    Example of embedding HYDRA7 node in your application.
    """
    # Optional: Configure via environment variables
    os.environ["HYDRA_SECRET"] = "MySecretNetworkKey"
    os.environ["HYDRA_SEEDS"] = "192.168.1.1:25000,192.168.1.2:25000"
    
    # Create a HYDRA7 node instance
    node = HydraNode()
    
    # Start the node (this will block)
    await node.start()


if __name__ == "__main__":
    # Run the node
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")
