import asyncio
import socket
import struct
import os
import hashlib
import json
import random
import time
import logging
import sys
import signal
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime

# --- [ CRITICAL DEPENDENCIES CHECK ] ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("\033[91m[FATAL] 'cryptography' lib missing. Run: pip install cryptography\033[0m")
    sys.exit(1)

# --- [ CONFIGURATION ] ---
# The Shared Secret. MUST match on all nodes to bypass DPI.
NETWORK_SECRET = os.getenv("HYDRA_SECRET", "Proprietary_Mesh_Key_V7_Genius")

# Validate secret strength
if len(NETWORK_SECRET) < 16:
    print("\033[91m[SECURITY WARNING] NETWORK_SECRET should be at least 16 characters!\033[0m")
    print("\033[91mUsing weak secret compromises the entire network security.\033[0m")

PORT_OVERRIDE = int(os.getenv("HYDRA_PORT", 0))

# Seed Nodes: "IP:Port" (Comma separated).
# Example: export HYDRA_SEEDS="145.2.3.4:25000,89.1.2.3:25000"
SEEDS = [s.strip() for s in os.getenv("HYDRA_SEEDS", "").split(",") if s.strip()]

# Constants with clear naming and rationale
SOCKS_PORT = 1080  # Standard SOCKS5 port
HYDRA_PORT_BASE = 25000  # Base port for HYDRA mesh (25000-30000 range)
MAX_PADDING = 256  # Maximum random padding to frustrate traffic analysis
KEEPALIVE_INTERVAL = 15  # Seconds between heartbeats (keep tunnels alive)
CONNECTION_TIMEOUT = 10  # Seconds to wait for connection establishment
BUFFER_SIZE = 65536  # 64KB buffer for data transfer
LOG_LEVEL = logging.INFO  # Default log level
TIMESTAMP_WINDOW = 30  # Seconds of clock skew tolerance (reduced from 60 for security)
MAX_FRAME_SIZE = BUFFER_SIZE + 1024  # Maximum frame size to prevent memory exhaustion
MAX_CONCURRENT_CONNECTIONS = 1000  # Maximum concurrent connections per node
IDLE_CONNECTION_TIMEOUT = 300  # Close idle connections after 5 minutes

# STUN Servers for WAN IP discovery
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.stunprotocol.org", 3478),
    ("stun.miwifi.com", 3478)
]

# Connectivity Check Targets (to determine if we are Exit Node)
CHECK_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("208.67.222.222", 53)]

# --- [ LOGGING ] ---
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s \033[92m[%(levelname)s]\033[0m %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("HYDRA")

# --- [ METRICS & MONITORING ] ---
class Metrics:
    """
    Simple metrics collection for monitoring HYDRA7 node health and performance.
    Tracks connections, bytes transferred, errors, and peer statistics.
    """
    def __init__(self):
        self.connections_total = 0
        self.connections_active = 0
        self.connections_failed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.frames_sent = 0
        self.frames_received = 0
        self.errors_total = 0
        self.peers_discovered = 0
        self.uptime_start = time.time()
        self.lock = asyncio.Lock()
    
    async def record_connection(self, success: bool = True):
        """Record a connection attempt"""
        async with self.lock:
            self.connections_total += 1
            if success:
                self.connections_active += 1
            else:
                self.connections_failed += 1
    
    async def record_disconnect(self):
        """Record a disconnection"""
        async with self.lock:
            if self.connections_active > 0:
                self.connections_active -= 1
    
    async def record_data(self, bytes_sent: int = 0, bytes_recv: int = 0):
        """Record data transfer"""
        async with self.lock:
            self.bytes_sent += bytes_sent
            self.bytes_received += bytes_recv
    
    async def record_frame(self, sent: bool = True):
        """Record frame processed"""
        async with self.lock:
            if sent:
                self.frames_sent += 1
            else:
                self.frames_received += 1
    
    async def record_error(self, error_type: str = "unknown"):
        """Record an error"""
        async with self.lock:
            self.errors_total += 1
            log.debug(f"Error recorded: {error_type}")
    
    async def record_peer_discovered(self):
        """Record peer discovery"""
        async with self.lock:
            self.peers_discovered += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        uptime = int(time.time() - self.uptime_start)
        return {
            'uptime_seconds': uptime,
            'connections_total': self.connections_total,
            'connections_active': self.connections_active,
            'connections_failed': self.connections_failed,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'frames_sent': self.frames_sent,
            'frames_received': self.frames_received,
            'errors_total': self.errors_total,
            'peers_discovered': self.peers_discovered,
        }
    
    def log_stats(self):
        """Log current statistics"""
        stats = self.get_stats()
        log.info(f"Stats: Active Conns={stats['connections_active']}, "
                f"Total Conns={stats['connections_total']}, "
                f"Sent={stats['bytes_sent']//1024}KB, "
                f"Recv={stats['bytes_received']//1024}KB, "
                f"Errors={stats['errors_total']}, "
                f"Uptime={stats['uptime_seconds']}s")

# Global metrics instance
metrics = Metrics()

# --- [ CRYPTO CORE ] ---
class Obfuscator:
    """
    Wraps the initial handshake in a stream cipher derived from the Network Secret.
    This prevents DPI from seeing X25519 keys or protocol headers.
    """
    def __init__(self):
        # Deterministic Key derivation from the Shared Secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'HYDRA_V7_SALT', # Static salt is fine for PSK context
            info=b'DPI_MASK_KEY'
        )
        self.key = hkdf.derive(NETWORK_SECRET.encode())

    def mask(self, data: bytes) -> bytes:
        # AES-CTR with random IV prefix.
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def unmask(self, data: bytes) -> bytes:
        if len(data) < 16: raise ValueError("Data too short for unmask")
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class SessionCrypto:
    """
    Per-Connection Security: X25519 Key Exchange -> ChaCha20-Poly1305.
    """
    def __init__(self):
        self.priv_key = x25519.X25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.tx_cipher = None
        self.rx_cipher = None
        self.tx_nonce = 0
        self.rx_nonce = 0
        self.tx_lock = asyncio.Lock()
        self.rx_lock = asyncio.Lock()

    def get_pub_bytes(self) -> bytes:
        return self.pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive(self, peer_pub_bytes: bytes, initiator: bool):
        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
            shared_secret = self.priv_key.exchange(peer_pub)
        except Exception:
            raise ValueError("Invalid Key Exchange")

        # Session Key Derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=hashlib.sha256(NETWORK_SECRET.encode()).digest(),
            info=b'HYDRA_SESSION_V7'
        )
        keys = hkdf.derive(shared_secret)
        
        if initiator:
            self.tx_cipher = ChaCha20Poly1305(keys[:32])
            self.rx_cipher = ChaCha20Poly1305(keys[32:])
        else:
            self.tx_cipher = ChaCha20Poly1305(keys[32:])
            self.rx_cipher = ChaCha20Poly1305(keys[:32])

    async def encrypt(self, data: bytes) -> bytes:
        async with self.tx_lock:
            # Check for nonce overflow (2^64 limit)
            if self.tx_nonce >= (2**64 - 1):
                raise ValueError("Nonce overflow - session must be renegotiated")
            nonce = struct.pack("!Q", self.tx_nonce).rjust(12, b'\x00')
            self.tx_nonce += 1
            return self.tx_cipher.encrypt(nonce, data, None)

    async def decrypt(self, data: bytes) -> bytes:
        async with self.rx_lock:
            # Check for nonce overflow (2^64 limit)
            if self.rx_nonce >= (2**64 - 1):
                raise ValueError("Nonce overflow - session must be renegotiated")
            nonce = struct.pack("!Q", self.rx_nonce).rjust(12, b'\x00')
            self.rx_nonce += 1
            return self.rx_cipher.decrypt(nonce, data, None)

# --- [ TRANSPORT LAYER ] ---
class SecureSocket:
    """
    Handles Framing, Encryption, Padding, and Heartbeats for secure communication.
    
    Features:
    - Encrypted frames using ChaCha20-Poly1305
    - Random padding for traffic analysis resistance  
    - Automatic heartbeats to keep connections alive
    - Nonce-based replay protection
    
    Frame Format:
        [FrameLen:2 bytes][Encrypted Payload]
        
    Payload Format (after decryption):
        [DataLen:2 bytes][Data][Random Padding]
    """
    def __init__(self, reader, writer, crypto):
        self.r = reader
        self.w = writer
        self.c = crypto
        self.obf = Obfuscator()
        self._closed = False
        self.last_activity = time.time()
        self.peer_addr = None
        
        # Get peer address for logging
        try:
            self.peer_addr = writer.get_extra_info('peername')
        except:
            self.peer_addr = "unknown"
        
        # OS Level Optimization
        sock = writer.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception as e:
                log.debug(f"Failed to set socket options: {e}")

    async def send_frame(self, data: bytes):
        """Send an encrypted frame with padding"""
        if self._closed: return
        try:
            # Padding to frustrate traffic analysis
            dlen = len(data)
            pad_len = random.randint(0, MAX_PADDING)
            padding = os.urandom(pad_len)
            
            # Payload: [Len:2][Data][Padding]
            payload = struct.pack("!H", dlen) + data + padding
            encrypted = await self.c.encrypt(payload)
            
            # Frame: [FrameLen:2][EncryptedBody]
            frame = struct.pack("!H", len(encrypted)) + encrypted
            self.w.write(frame)
            await self.w.drain()
            self.last_activity = time.time()
            
            # Record metrics
            await metrics.record_frame(sent=True)
            await metrics.record_data(bytes_sent=len(frame))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning(f"Send frame failed to {self.peer_addr}: {e}")
            await metrics.record_error("send_frame_failed")
            await self.close()
            raise

    async def recv_frame(self) -> Optional[bytes]:
        """
        Reads a frame, handles Heartbeats transparently.
        Returns None on disconnect or error.
        
        Raises:
            ValueError: Frame size exceeds maximum allowed
            asyncio.TimeoutError: Read operation timed out
        """
        while not self._closed:
            try:
                # 1. Read Frame Length with timeout to prevent hangs
                try:
                    async with asyncio.timeout(CONNECTION_TIMEOUT):
                        head = await self.r.readexactly(2)
                except asyncio.TimeoutError:
                    log.warning(f"Read timeout from {self.peer_addr}")
                    await metrics.record_error("read_timeout")
                    await self.close()
                    return None
                
                cipher_len = struct.unpack("!H", head)[0]
                
                # Sanity check against maximum frame size
                if cipher_len > MAX_FRAME_SIZE:
                    log.error(f"Oversized frame ({cipher_len} bytes) from {self.peer_addr}")
                    await metrics.record_error("oversized_frame")
                    raise ValueError(f"Frame size {cipher_len} exceeds maximum {MAX_FRAME_SIZE}")

                # 2. Read Ciphertext with timeout
                try:
                    async with asyncio.timeout(CONNECTION_TIMEOUT):
                        ciphertext = await self.r.readexactly(cipher_len)
                except asyncio.TimeoutError:
                    log.warning(f"Read timeout waiting for frame body from {self.peer_addr}")
                    await metrics.record_error("read_timeout")
                    await self.close()
                    return None
                
                # 3. Decrypt
                try:
                    plaintext = await self.c.decrypt(ciphertext)
                except Exception as e:
                    log.warning(f"Decryption failed from {self.peer_addr}: {e}")
                    await metrics.record_error("decryption_failed")
                    await self.close()
                    return None
                
                # 4. Parse Inner payload
                if len(plaintext) < 2:
                    log.warning(f"Invalid frame format from {self.peer_addr}")
                    await metrics.record_error("invalid_frame")
                    await self.close()
                    return None
                    
                real_len = struct.unpack("!H", plaintext[:2])[0]
                if real_len > len(plaintext) - 2:
                    log.warning(f"Frame data length mismatch from {self.peer_addr}")
                    await metrics.record_error("invalid_frame")
                    await self.close()
                    return None
                    
                data = plaintext[2:2+real_len]
                
                # Record metrics
                await metrics.record_frame(sent=False)
                await metrics.record_data(bytes_recv=len(head) + cipher_len)
                self.last_activity = time.time()
                
                # Handle Internal Commands (Heartbeat)
                if len(data) == 1 and data[0] == 0x02: # HEARTBEAT_ACK
                    log.debug(f"Heartbeat received from {self.peer_addr}")
                    continue
                
                return data

            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as e:
                log.debug(f"Connection closed from {self.peer_addr}: {e}")
                await metrics.record_error("connection_closed")
                await self.close()
                return None
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning(f"Transport error from {self.peer_addr}: {e}")
                await metrics.record_error("transport_error")
                await self.close()
                return None

    async def send_heartbeat(self):
        if self._closed: return
        try:
            await self.send_frame(b'\x02')
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    async def handshake_init(self) -> bool:
        """Client-side Handshake"""
        try:
            # 1. Obfuscated Hello
            my_pub = self.c.get_pub_bytes()
            # Random entropy prefix to shift bits
            entropy = os.urandom(random.randint(16, 64))
            # Format: [EntropyLen:1][Entropy][PubKey:32]
            raw = bytes([len(entropy)]) + entropy + my_pub
            masked = self.obf.mask(raw)
            
            # Send: [Len:2][MaskedData]
            self.w.write(struct.pack("!H", len(masked)) + masked)
            await self.w.drain()
            
            # 2. Receive Peer Hello
            plen = struct.unpack("!H", await self.r.readexactly(2))[0]
            peer_masked = await self.r.readexactly(plen)
            peer_raw = self.obf.unmask(peer_masked)
            
            e_len = peer_raw[0]
            peer_pub = peer_raw[1+e_len : 1+e_len+32]
            
            self.c.derive(peer_pub, True)
            
            # 3. Network Auth (Timestamp Proof)
            ts = int(time.time())
            # Proof = SHA256(Secret + timestamp)
            proof = hashlib.sha256(NETWORK_SECRET.encode() + struct.pack("!Q", ts)).digest()
            await self.send_frame(struct.pack("!Q", ts) + proof)
            
            return True
        except Exception as e:
            log.warning(f"Handshake Init Failed: {e}")
            await self.close()
            return False

    async def handshake_resp(self) -> bool:
        """Server-side Handshake"""
        try:
            # 1. Receive Client Hello
            plen = struct.unpack("!H", await self.r.readexactly(2))[0]
            if plen > 1024: raise ValueError("Hello too big")
            
            peer_masked = await self.r.readexactly(plen)
            peer_raw = self.obf.unmask(peer_masked)
            
            e_len = peer_raw[0]
            peer_pub = peer_raw[1+e_len : 1+e_len+32]
            
            # 2. Send My Hello
            my_pub = self.c.get_pub_bytes()
            entropy = os.urandom(random.randint(16, 64))
            raw = bytes([len(entropy)]) + entropy + my_pub
            masked = self.obf.mask(raw)
            
            self.w.write(struct.pack("!H", len(masked)) + masked)
            await self.w.drain()
            
            self.c.derive(peer_pub, False)
            
            # 3. Verify Auth
            auth_frame = await self.recv_frame()
            if not auth_frame: return False
            
            if len(auth_frame) < 40:  # 8 bytes timestamp + 32 bytes SHA256
                log.warning(f"Auth Failed: Invalid frame length from {self.peer_addr}")
                await metrics.record_error("auth_invalid_frame")
                return False
            
            ts = struct.unpack("!Q", auth_frame[:8])[0]
            proof = auth_frame[8:]
            
            # Tighter replay window (reduced from 60s to 30s for better security)
            time_diff = abs(time.time() - ts)
            if time_diff > TIMESTAMP_WINDOW:
                log.warning(f"Auth Failed: Timestamp outside window ({time_diff:.1f}s) from {self.peer_addr}")
                await metrics.record_error("auth_replay_window")
                return False
            
            expected = hashlib.sha256(NETWORK_SECRET.encode() + auth_frame[:8]).digest()
            if proof != expected:
                log.warning(f"Auth Failed: Wrong secret from {self.peer_addr}")
                await metrics.record_error("auth_wrong_secret")
                return False
            
            log.debug(f"Handshake successful with {self.peer_addr}")
            return True
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning(f"Handshake Resp Failed from {self.peer_addr}: {e}")
            await metrics.record_error("handshake_failed")
            await self.close()
            return False

    async def close(self):
        """Close the secure socket and clean up resources"""
        if self._closed: return
        self._closed = True
        try:
            await metrics.record_disconnect()
            self.w.close()
            await self.w.wait_closed()
        except: pass

# --- [ DISCOVERY & STATE ] ---
class PeerManager:
    def __init__(self, port):
        self.my_port = port
        self.peers: Dict[str, Dict] = {} 
        self.lock = asyncio.Lock()
        self.my_external_ip: Optional[str] = None
        self.am_i_exit = False
        self.bunker_mode = False

        # Load Seeds
        for seed in SEEDS:
            try:
                if ":" in seed:
                    ip, p = seed.split(":")
                    self.add_static_peer(ip, int(p))
                else:
                    self.add_static_peer(seed, port)
            except: pass

    def add_static_peer(self, ip, port):
        self.peers[ip] = {'ts': time.time(), 'exit': True, 'port': port}

    async def update_peer(self, ip, is_exit, port):
        if ip == self.my_external_ip or ip.startswith("127."): return
        async with self.lock:
            # Refresh if existing, else add
            self.peers[ip] = {
                'ts': time.time(),
                'exit': is_exit,
                'port': port
            }

    async def get_best_exit(self) -> Optional[Tuple[str, int]]:
        async with self.lock:
            # Filter for exits seen in last 5 mins
            now = time.time()
            candidates = [
                (ip, d['port']) for ip, d in self.peers.items()
                if d['exit'] and (now - d['ts'] < 300)
            ]
            if not candidates: 
                # Fallback to seeds if they are in the list
                candidates = [
                    (ip, d['port']) for ip, d in self.peers.items() 
                    if d['exit'] # seeds are usually exits
                ]
            
            if not candidates: return None
            return random.choice(candidates)

    def get_sync_list(self) -> List[Dict]:
        """Return subset of peers for PEX"""
        # Return 20 random active peers
        active = [
            {'ip': k, 'port': v['port'], 'exit': v['exit']}
            for k, v in self.peers.items()
            if time.time() - v['ts'] < 3600
        ]
        return random.sample(active, min(len(active), 20))

    async def cleanup(self):
        async with self.lock:
            now = time.time()
            # Remove peers older than 1 hour
            dead = [k for k, v in self.peers.items() if now - v['ts'] > 3600]
            for k in dead: del self.peers[k]

class StunClient:
    """Robust STUN to find public IP"""
    async def get_ip(self) -> Optional[str]:
        for server, port in STUN_SERVERS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                # Simple Binding Request
                txn = os.urandom(12)
                req = b'\x00\x01\x00\x00\x21\x12\xA4\x42' + txn
                sock.sendto(req, (server, port))
                
                resp, _ = sock.recvfrom(2048)
                
                # Parse Mapped Address (IPv4 only logic for simplicity)
                # Header(20) -> Attributes
                if len(resp) < 20: 
                    sock.close()
                    continue
                
                idx = 20
                while idx < len(resp):
                    if idx + 4 > len(resp):
                        break
                    atype = struct.unpack("!H", resp[idx:idx+2])[0]
                    alen = struct.unpack("!H", resp[idx+2:idx+4])[0]
                    idx += 4
                    
                    if atype == 0x0001: # Mapped Address
                        if idx + alen > len(resp):
                            break
                        family = resp[idx+1]
                        if family == 0x01: # IPv4
                            if idx + 8 <= len(resp):
                                ip = socket.inet_ntoa(resp[idx+4:idx+8])
                                sock.close()
                                return ip
                    idx += alen
                sock.close()
            except Exception:
                try:
                    sock.close()
                except:
                    pass
                continue
        return None

# --- [ NODE LOGIC ] ---
class HydraNode:
    """
    Main HYDRA7 node that coordinates all mesh network operations.
    
    Responsibilities:
    - Start and manage transport servers (HYDRA tunnel + SOCKS5 proxy)
    - Perform peer discovery and exchange
    - Route traffic through the mesh network
    - Monitor node health and connectivity
    """
    def __init__(self):
        self.port = self._get_port()
        self.peers = PeerManager(self.port)
        self.stun = StunClient()
        self.running = True
        self.shutdown_event = asyncio.Event()
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._shutdown(s)))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
        except Exception as e:
            log.debug(f"Could not setup signal handlers: {e}")
    
    async def _shutdown(self, sig):
        """Handle shutdown signal gracefully"""
        log.info(f"\n\033[93m[SHUTDOWN] Received signal {sig}, initiating graceful shutdown...\033[0m")
        self.running = False
        self.shutdown_event.set()
        
        # Log final statistics
        metrics.log_stats()

    def _get_port(self):
        if PORT_OVERRIDE > 0: return PORT_OVERRIDE
        # Deterministic port based on Secret
        h = hashlib.sha256(NETWORK_SECRET.encode()).digest()
        return HYDRA_PORT_BASE + (int.from_bytes(h[:2], 'big') % 5000)

    async def start(self):
        print(f"\033[96m[HYDRA v7] Starting on 0.0.0.0:{self.port}...\033[0m")
        print(f"Secret Hash: {hashlib.sha256(NETWORK_SECRET.encode()).hexdigest()[:8]}")
        
        # Display configuration
        log.info(f"Configuration: Max Connections={MAX_CONCURRENT_CONNECTIONS}, "
                f"Timeout={CONNECTION_TIMEOUT}s, Timestamp Window={TIMESTAMP_WINDOW}s")

        # 1. Start Transport Servers
        try:
            srv = await asyncio.start_server(self.handle_tunnel, '0.0.0.0', self.port)
            socks = await asyncio.start_server(self.handle_socks, '127.0.0.1', SOCKS_PORT)
            log.info(f"HYDRA tunnel listening on 0.0.0.0:{self.port}")
            log.info(f"SOCKS5 proxy listening on 127.0.0.1:{SOCKS_PORT}")
        except OSError as e:
            log.error(f"Port bind failed: {e}")
            print(f"\033[91m[ERROR] Port bind failed: {e}\033[0m")
            return

        # 2. Initial Setup
        my_ip = await self.stun.get_ip()
        if my_ip:
            log.info(f"Public IP: {my_ip}")
            self.peers.my_external_ip = my_ip
        else:
            log.warning("STUN Failed. Entering Bunker Mode (Hidden Node).")
            self.peers.bunker_mode = True

        # 3. Start background tasks
        tasks = [
            self.run_server(srv),
            self.run_server(socks),
            self.task_connectivity_check(),
            self.task_pex(),
            self.task_cleanup(),
            self.task_stats_logger(),  # New task for periodic stats logging
        ]

        log.info("\033[92m[READY] Node initialized and ready to serve\033[0m")

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            log.info("\nReceived interrupt, shutting down...")
            self.running = False
        finally:
            # Final cleanup
            log.info("Node stopped")
            metrics.log_stats()

    async def run_server(self, srv):
        """Run a server until shutdown"""
        async with srv:
            try:
                await srv.serve_forever()
            except asyncio.CancelledError:
                log.debug("Server task cancelled")

    # --- BACKGROUND TASKS ---
    async def task_stats_logger(self):
        """Periodically log node statistics"""
        while self.running:
            await asyncio.sleep(60)  # Log stats every minute
            if self.running:
                metrics.log_stats()
    
    async def task_connectivity_check(self):
        """Check if this node can act as an Exit Node"""
        while self.running:
            success = False
            for h, p in CHECK_TARGETS:
                try:
                    r, w = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
                    w.close()
                    await w.wait_closed()
                    success = True
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    log.debug(f"Connectivity check failed for {h}:{p}: {e}")
            
            # State Transition Logic
            if success and not self.peers.am_i_exit:
                log.info("\033[92m[ROLE] Promoted to EXIT NODE\033[0m")
            elif not success and self.peers.am_i_exit:
                log.warning("\033[93m[ROLE] Demoted to RELAY NODE\033[0m")
            
            self.peers.am_i_exit = success
            await asyncio.sleep(60)

    async def task_pex(self):
        """Peer Exchange Loop"""
        while self.running:
            # Wait for some peers to exist
            target = await self.peers.get_best_exit()
            if not target:
                # If no peers, try seeds forcefully
                for s in SEEDS:
                    if ":" in s:
                        ip, p = s.split(":")
                        asyncio.create_task(self.do_pex(ip, int(p)))
                await asyncio.sleep(10)
                continue

            # Sync with a random active peer
            ip, port = target
            asyncio.create_task(self.do_pex(ip, port))
            await asyncio.sleep(30)

    async def task_cleanup(self):
        while self.running:
            await asyncio.sleep(300)
            await self.peers.cleanup()

    async def do_pex(self, ip, port):
        """Connect to peer, swap lists, disconnect"""
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
            ss = SecureSocket(r, w, SessionCrypto())
            if not await ss.handshake_init(): return
            
            # CMD 0x99: PEX
            # Payload: JSON
            my_list = self.peers.get_sync_list()
            # Include myself if not bunker mode
            if not self.peers.bunker_mode and self.peers.my_external_ip:
                my_list.append({
                    'ip': self.peers.my_external_ip,
                    'port': self.port,
                    'exit': self.peers.am_i_exit
                })
            
            data = json.dumps(my_list).encode()
            # Send: [0x99][Data]
            await ss.send_frame(b'\x99' + data)
            
            # Wait for reply? No, UDP-style fire and forget is safer for latency,
            # but for TCP mesh, receiving their list helps.
            # Let's try to read one frame then close.
            try:
                frame = await asyncio.wait_for(ss.recv_frame(), 5)
                if frame and frame[0] == 0x99:
                    self.process_pex_blob(frame[1:])
            except: pass
            
            await ss.close()
        except Exception:
            pass

    def process_pex_blob(self, blob):
        try:
            data = json.loads(blob)
            count = 0
            for p in data:
                asyncio.create_task(self.peers.update_peer(p['ip'], p['exit'], p['port']))
                count += 1
            # log.debug(f"PEX: Learned {count} peers")
        except: pass

    # --- TUNNEL HANDLER (INBOUND) ---
    async def handle_tunnel(self, r, w):
        ss = SecureSocket(r, w, SessionCrypto())
        try:
            if not await ss.handshake_resp(): return
            
            # Loop for commands
            while True:
                frame = await ss.recv_frame()
                if not frame: break # Closed
                
                cmd = frame[0]
                
                # 0x01: CONNECT (Proxy)
                if cmd == 0x01:
                    # Validate frame length
                    if len(frame) < 2:
                        break
                    hlen = frame[1]
                    if len(frame) < 2 + hlen + 2:
                        break
                    host = frame[2:2+hlen].decode()
                    port = struct.unpack("!H", frame[2+hlen:2+hlen+2])[0]
                    
                    if self.peers.am_i_exit:
                        await self.run_exit(ss, host, port)
                    else:
                        await self.run_relay(ss, frame)
                    break # Tunnel is consumed
                
                # 0x99: PEX
                elif cmd == 0x99:
                    self.process_pex_blob(frame[1:])
                    # Reply with my list
                    my_list = self.peers.get_sync_list()
                    if not self.peers.bunker_mode and self.peers.my_external_ip:
                        my_list.append({
                            'ip': self.peers.my_external_ip,
                            'port': self.port,
                            'exit': self.peers.am_i_exit
                        })
                    rep = json.dumps(my_list).encode()
                    await ss.send_frame(b'\x99' + rep)
                    # Don't break, keep connection potentially open or close
                    break
                    
        except Exception:
            await ss.close()

    # --- ROUTING (OUTBOUND) ---
    async def run_exit(self, client_ss, host, port):
        """I am the exit. Connect to Internet."""
        target_w = None
        try:
            target_r, target_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), CONNECTION_TIMEOUT
            )
            # Signal OK
            await client_ss.send_frame(b'\x00')
            
            # Start Bi-directional Pipe
            await self.pipe_secure_plain(client_ss, target_r, target_w)
            
        except Exception:
            await client_ss.send_frame(b'\xFF') # Error
            if target_w:
                target_w.close()
                await target_w.wait_closed()

    async def run_relay(self, client_ss, init_packet):
        """I am a relay. Find next hop."""
        # Retry logic: Try up to 3 different exits
        for _ in range(3):
            exit_node = await self.peers.get_best_exit()
            if not exit_node: break
            
            ip, port = exit_node
            next_ss = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECTION_TIMEOUT)
                next_ss = SecureSocket(r, w, SessionCrypto())
                if not await next_ss.handshake_init(): raise Exception()
                
                # Forward original Connect packet
                await next_ss.send_frame(init_packet)
                
                # Wait for Ack
                resp = await next_ss.recv_frame()
                if not resp or resp != b'\x00': raise Exception()
                
                # Success. Relay OK to client.
                await client_ss.send_frame(b'\x00')
                
                # Bridge
                await self.bridge_secure(client_ss, next_ss)
                return
                
            except Exception:
                if next_ss: await next_ss.close()
                continue # Try next exit
        
        # All failed
        await client_ss.send_frame(b'\xFF')

    # --- SOCKS5 FRONTEND ---
    async def handle_socks(self, r, w):
        try:
            # Auth
            ver = await r.read(1)
            if ver != b'\x05':
                w.close()
                await w.wait_closed()
                return
            nm = (await r.read(1))[0]
            await r.read(nm)
            w.write(b'\x05\x00'); await w.drain()
            
            # Request
            head = await r.readexactly(4)
            cmd = head[1]
            if cmd != 1: # CONNECT only
                w.close()
                await w.wait_closed()
                return
            
            atyp = head[3]
            if atyp == 1: # IPv4
                addr = socket.inet_ntoa(await r.readexactly(4))
            elif atyp == 3: # Domain
                l = (await r.readexactly(1))[0]
                addr = (await r.readexactly(l)).decode()
            else:
                w.close()
                await w.wait_closed()
                return
            
            port = struct.unpack("!H", await r.readexactly(2))[0]
            
            # Execute
            if self.peers.am_i_exit:
                await self.socks_direct(r, w, addr, port)
            else:
                await self.socks_tunnel(r, w, addr, port)
                
        except Exception:
            try:
                w.close()
                await w.wait_closed()
            except:
                pass

    async def socks_direct(self, cr, cw, host, port):
        tw = None
        try:
            tr, tw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            cw.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'); await cw.drain()
            await self.pipe_plain(cr, cw, tr, tw)
        except:
            try:
                cw.close()
                await cw.wait_closed()
            except:
                pass
            if tw:
                tw.close()
                try:
                    await tw.wait_closed()
                except:
                    pass

    async def socks_tunnel(self, cr, cw, host, port):
        # Retry loop for client experience
        for _ in range(2):
            exit_node = await self.peers.get_best_exit()
            if not exit_node: break
            
            ss = None
            try:
                ip, p = exit_node
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), CONNECTION_TIMEOUT)
                ss = SecureSocket(r, w, SessionCrypto())
                if not await ss.handshake_init(): raise Exception()
                
                # Build Packet: [0x01][HLen][Host][Port]
                payload = b'\x01' + bytes([len(host)]) + host.encode() + struct.pack("!H", port)
                await ss.send_frame(payload)
                
                res = await ss.recv_frame()
                if res != b'\x00': raise Exception()
                
                cw.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'); await cw.drain()
                await self.pipe_secure_plain(ss, cr, cw)
                return
            except:
                if ss: await ss.close()
        
        # Fail
        try:
            cw.close()
            await cw.wait_closed()
        except:
            pass

    # --- PIPING MECHANICS (HEARTBEAT AWARE) ---
    async def keepalive_sender(self, ss: SecureSocket):
        """Sends heartbeats during idle times in a pipe"""
        while not ss._closed:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if time.time() - ss.last_activity > KEEPALIVE_INTERVAL:
                try: await ss.send_heartbeat()
                except: break

    async def pipe_plain(self, r1, w1, r2, w2):
        """Plain TCP <-> Plain TCP"""
        async def cp(r, w):
            try:
                while True:
                    d = await r.read(BUFFER_SIZE)
                    if not d: break
                    w.write(d); await w.drain()
            except: pass
            finally:
                try: w.close()
                except: pass
        await asyncio.gather(cp(r1, w2), cp(r2, w1))

    async def pipe_secure_plain(self, ss: SecureSocket, pr, pw):
        """SecureSocket <-> Plain TCP"""
        # Start Heartbeat task
        ka = asyncio.create_task(self.keepalive_sender(ss))
        
        async def s2p():
            try:
                while True:
                    d = await ss.recv_frame()
                    if not d: break
                    pw.write(d); await pw.drain()
            except: pass
            finally:
                try: pw.close()
                except: pass

        async def p2s():
            try:
                while True:
                    d = await pr.read(BUFFER_SIZE)
                    if not d: break
                    await ss.send_frame(d)
            except: pass
            # We don't close SS here, wait for s2p

        await asyncio.gather(s2p(), p2s())
        ka.cancel()
        await ss.close()

    async def bridge_secure(self, s1: SecureSocket, s2: SecureSocket):
        """Secure <-> Secure (Relay)"""
        ka1 = asyncio.create_task(self.keepalive_sender(s1))
        ka2 = asyncio.create_task(self.keepalive_sender(s2))
        
        async def cp(src, dst):
            try:
                while True:
                    d = await src.recv_frame()
                    if not d: break
                    await dst.send_frame(d)
            except: pass
        
        await asyncio.gather(cp(s1, s2), cp(s2, s1))
        ka1.cancel(); ka2.cancel()
        await s1.close(); await s2.close()

# --- [ ENTRY POINT ] ---
if __name__ == "__main__":
    # Maximize Performance
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    else:
        try:
            import uvloop
            uvloop.install()
        except: pass

    node = HydraNode()
    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        pass