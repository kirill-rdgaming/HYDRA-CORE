# HYDRA7 - Secure Mesh Network

HYDRA7 is a production-ready secure mesh network with built-in DPI (Deep Packet Inspection) evasion and multi-hop routing capabilities. It provides a distributed proxy network with advanced cryptographic protection and automatic peer discovery.

## Features

- **Military-Grade Encryption**: X25519 key exchange with ChaCha20-Poly1305 AEAD
- **DPI Evasion**: Obfuscated handshakes to bypass network inspection
- **Mesh Architecture**: Automatic peer discovery and multi-hop routing
- **SOCKS5 Proxy**: Local proxy interface for applications
- **Exit/Relay Nodes**: Automatic role detection based on connectivity
- **Heartbeat Protocol**: Keepalive mechanism for stable connections
- **Traffic Padding**: Random padding to frustrate traffic analysis

## Installation

### From PyPI

```bash
pip install hydra7
```

### From Source

```bash
git clone https://github.com/kirill-rdgaming/HYDRA-CORE.git
cd HYDRA-CORE
pip install -e .
```

### With Performance Enhancements

For better performance on Linux/macOS, install with uvloop:

```bash
pip install hydra7[performance]
```

## Quick Start

### Running as a standalone node

```bash
# Using the command-line tool
hydra7

# Or using Python module syntax
python -m hydra7.cli
```

### With custom configuration

```bash
# Specify custom network secret and seed nodes
hydra7 --secret "MySecretKey" --seeds "192.168.1.1:25000,192.168.1.2:25000"

# Custom ports
hydra7 --port 30000 --socks-port 9050

# Verbose logging
hydra7 -v
```

### Using environment variables

```bash
export HYDRA_SECRET="MySecretKey"
export HYDRA_SEEDS="192.168.1.1:25000,192.168.1.2:25000"
export HYDRA_PORT=30000

hydra7
```

## Using as a Library

HYDRA7 can be embedded into your Python applications:

```python
import asyncio
from hydra7 import HydraNode

async def main():
    # Create and configure node
    node = HydraNode()
    
    # Start the node
    await node.start()

if __name__ == "__main__":
    asyncio.run(main())
```

### Public API

The following classes and functions are available in the public API:

- `HydraNode`: Main node class for running a HYDRA7 node
- `SessionCrypto`: Cryptographic session management
- `SecureSocket`: Encrypted socket wrapper
- `PeerManager`: Peer discovery and management
- `StunClient`: STUN client for public IP discovery
- `Obfuscator`: DPI evasion obfuscation layer

## Configuration

### Environment Variables

- `HYDRA_SECRET`: Network shared secret (default: auto-generated)
- `HYDRA_PORT`: Override default port (default: derived from secret)
- `HYDRA_SEEDS`: Comma-separated list of seed nodes (IP:PORT format)
- `HYDRA_SNI`: SNI domain for TLS camouflage to bypass DPI (optional)

### Command-Line Options

```
usage: hydra7 [-h] [--version] [--port PORT] [--secret SECRET] 
              [--seeds SEEDS] [--socks-port PORT] [--sni DOMAIN] [-v]

HYDRA7 - Secure Mesh Network with DPI Evasion

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --port PORT           Override the default HYDRA port
  --secret SECRET       Network secret key (or set HYDRA_SECRET env var)
  --seeds SEEDS         Comma-separated list of seed nodes (IP:PORT)
  --socks-port PORT     Local SOCKS5 proxy port (default: 1080)
  --sni DOMAIN          SNI domain for TLS camouflage (e.g., google.com)
  -v, --verbose         Enable verbose logging (DEBUG level)
```

### TLS Camouflage (Advanced DPI Bypass)

HYDRA7 includes a sophisticated TLS camouflage feature that disguises mesh traffic as legitimate HTTPS connections to bypass SNI-based filtering and strict censorship:

```bash
# Disguise traffic as HTTPS to google.com
hydra7 --sni google.com

# Or use environment variable
export HYDRA_SNI=cloudflare.com
hydra7
```

**Features:**
- Support for TLS 1.3, 1.2, 1.1, 1.0, and SSL 3.0
- Realistic browser fingerprints (Chrome, Firefox, Safari)
- GREASE values to prevent TLS ossification detection
- Complete handshake simulation with fake certificates
- Traffic fragmentation and timing jitter for maximum realism
- Makes traffic **indistinguishable** from real HTTPS connections

This makes connections appear as normal HTTPS traffic to whitelisted domains, effectively bypassing SNI-based filtering.

## How It Works

1. **Node Startup**: Node starts and performs STUN discovery to find its public IP
2. **Role Detection**: Checks connectivity to determine if it can be an exit node
3. **Peer Discovery**: Connects to seed nodes and exchanges peer lists (PEX)
4. **Secure Tunneling**: Establishes encrypted tunnels using X25519 + ChaCha20-Poly1305
5. **Traffic Routing**: Routes SOCKS5 traffic through the mesh to exit nodes

## Security Considerations

- Always use a strong, unique `HYDRA_SECRET` for your network
- The secret must be shared among all nodes in the network
- Network traffic is encrypted end-to-end
- Handshakes are obfuscated to prevent DPI detection
- Automatic replay protection with timestamp validation (±30 seconds)

## Requirements

- Python 3.8 or higher
- cryptography library (automatically installed)
- Optional: uvloop for better performance (Linux/macOS)

## Development

### Setting up development environment

```bash
git clone https://github.com/kirill-rdgaming/HYDRA-CORE.git
cd HYDRA-CORE
pip install -e .[dev]
```

### Running tests

```bash
pytest
```

### Code formatting

```bash
black hydra7/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please visit:
https://github.com/kirill-rdgaming/HYDRA-CORE/issues
