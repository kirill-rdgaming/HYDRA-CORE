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

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("\033[91m[FATAL] 'cryptography' lib missing. Run: pip install cryptography\033[0m")
    sys.exit(1)

NETWORK_SECRET = os.getenv("HYDRA_SECRET", "Proprietary_Mesh_Key_V7_Genius")

if len(NETWORK_SECRET) < 16:
    print("\033[91m[SECURITY WARNING] NETWORK_SECRET should be at least 16 characters!\033[0m")
    print("\033[91mUsing weak secret compromises the entire network security.\033[0m")

PORT_OVERRIDE = int(os.getenv("HYDRA_PORT", 0))

SEEDS = [s.strip() for s in os.getenv("HYDRA_SEEDS", "").split(",") if s.strip()]

SNI_DOMAIN = os.getenv("HYDRA_SNI", "").strip()

SOCKS_PORT = 1080
HYDRA_PORT_BASE = 25000
MAX_PADDING = 256
KEEPALIVE_INTERVAL = 15
CONNECTION_TIMEOUT = 10
BUFFER_SIZE = 65536
LOG_LEVEL = logging.INFO
TIMESTAMP_WINDOW = 30
MAX_FRAME_SIZE = BUFFER_SIZE + 1024
MAX_CONCURRENT_CONNECTIONS = 1000
IDLE_CONNECTION_TIMEOUT = 300

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.stunprotocol.org", 3478),
    ("stun.miwifi.com", 3478)
]

CHECK_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("208.67.222.222", 53)]

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s \033[92m[%(levelname)s]\033[0m %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("HYDRA")

class Metrics:
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
        async with self.lock:
            self.connections_total += 1
            if success:
                self.connections_active += 1
            else:
                self.connections_failed += 1
    
    async def record_disconnect(self):
        async with self.lock:
            if self.connections_active > 0:
                self.connections_active -= 1
    
    async def record_data(self, bytes_sent: int = 0, bytes_recv: int = 0):
        async with self.lock:
            self.bytes_sent += bytes_sent
            self.bytes_received += bytes_recv
    
    async def record_frame(self, sent: bool = True):
        async with self.lock:
            if sent:
                self.frames_sent += 1
            else:
                self.frames_received += 1
    
    async def record_error(self, error_type: str = "unknown"):
        async with self.lock:
            self.errors_total += 1
            log.debug(f"Error recorded: {error_type}")
    
    async def record_peer_discovered(self):
        async with self.lock:
            self.peers_discovered += 1
    
    def get_stats(self) -> Dict[str, Any]:
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
        stats = self.get_stats()
        log.info(f"Stats: Active Conns={stats['connections_active']}, "
                f"Total Conns={stats['connections_total']}, "
                f"Sent={stats['bytes_sent']//1024}KB, "
                f"Recv={stats['bytes_received']//1024}KB, "
                f"Errors={stats['errors_total']}, "
                f"Uptime={stats['uptime_seconds']}s")

metrics = Metrics()

class Obfuscator:
    def __init__(self):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'HYDRA_V7_SALT',
            info=b'DPI_MASK_KEY'
        )
        self.key = hkdf.derive(NETWORK_SECRET.encode())

    def mask(self, data: bytes) -> bytes:
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

class TlsCamouflage:
    
    TLS_VERSION_SSL3 = 0x0300
    TLS_VERSION_TLS10 = 0x0301
    TLS_VERSION_TLS11 = 0x0302
    TLS_VERSION_TLS12 = 0x0303
    TLS_VERSION_TLS13 = 0x0304
    
    CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
    CONTENT_TYPE_ALERT = 0x15
    CONTENT_TYPE_HANDSHAKE = 0x16
    CONTENT_TYPE_APPLICATION_DATA = 0x17
    CONTENT_TYPE_HEARTBEAT = 0x18
    
    HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
    HANDSHAKE_TYPE_SERVER_HELLO = 0x02
    HANDSHAKE_TYPE_NEW_SESSION_TICKET = 0x04
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08
    HANDSHAKE_TYPE_CERTIFICATE = 0x0b
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0f
    HANDSHAKE_TYPE_FINISHED = 0x14
    
    BROWSER_PROFILES = {
        'chrome': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'ciphers': [0x1301, 0x1302, 0x1303, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 
                       0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 
                       0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 
                       0x003c, 0x0035, 0x002f, 0x00ff],
            'extensions': ['grease', 'sni', 'extended_master_secret', 'renegotiation_info', 
                          'supported_groups', 'ec_point_formats', 'session_ticket', 
                          'application_layer_protocol_negotiation', 'status_request', 
                          'signature_algorithms', 'signed_certificate_timestamp', 
                          'key_share', 'psk_key_exchange_modes', 'supported_versions', 
                          'compress_certificate', 'application_settings', 'grease', 'padding'],
            'alpn': [b'h2', b'http/1.1'],
        },
        'firefox': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'ciphers': [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8,
                       0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009f,
                       0x009e, 0x006b, 0x0067, 0x0039, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c,
                       0x0035, 0x002f, 0x00ff],
            'extensions': ['sni', 'extended_master_secret', 'renegotiation_info', 
                          'supported_groups', 'ec_point_formats', 'session_ticket',
                          'application_layer_protocol_negotiation', 'status_request',
                          'delegated_credentials', 'key_share', 'supported_versions',
                          'signature_algorithms', 'psk_key_exchange_modes', 'record_size_limit'],
            'alpn': [b'h2', b'http/1.1'],
        },
        'safari': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'ciphers': [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8,
                       0xc024, 0xc023, 0xc028, 0xc027, 0x009f, 0x009e, 0xc00a, 0xc009, 0xc014,
                       0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x002f, 0x0035, 0x000a, 0x00ff],
            'extensions': ['grease', 'sni', 'extended_master_secret', 'renegotiation_info',
                          'supported_groups', 'ec_point_formats', 'session_ticket',
                          'application_layer_protocol_negotiation', 'status_request',
                          'signature_algorithms', 'signed_certificate_timestamp',
                          'key_share', 'psk_key_exchange_modes', 'supported_versions', 'grease'],
            'alpn': [b'h2', b'http/1.1'],
        },
    }
    
    GREASE_VALUES = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                     0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]
    
    def __init__(self, sni_domain: str, version: str = "1.3", browser: str = "chrome"):
        self.sni_domain = sni_domain
        self.version = version
        self.browser = browser if browser in self.BROWSER_PROFILES else "chrome"
        self.profile = self.BROWSER_PROFILES[self.browser]
        
        self.version_map = {
            "ssl3": self.TLS_VERSION_SSL3,
            "1.0": self.TLS_VERSION_TLS10,
            "1.1": self.TLS_VERSION_TLS11,
            "1.2": self.TLS_VERSION_TLS12,
            "1.3": self.TLS_VERSION_TLS13,
        }
        
        self.protocol_version = self.version_map.get(version, self.TLS_VERSION_TLS13)
        
        self.session_id = os.urandom(32)
        self.client_random = struct.pack("!I", int(time.time())) + os.urandom(28)
        self.server_random = struct.pack("!I", int(time.time())) + os.urandom(28)
        
        grease_values = self.GREASE_VALUES.copy()
        random.shuffle(grease_values)
        self.grease_cipher = grease_values[0]
        self.grease_extension = grease_values[1]
        self.grease_group = grease_values[2]
        self.grease_version = grease_values[3]
        
        self.record_size_distribution = [256, 512, 1024, 2048, 4096, 8192, 16384]
        self.timing_jitter_ms = (10, 100)
        
        self.handshake_complete = False
        self.sent_records = 0
        self.recv_records = 0
    
    def _build_grease_extension(self) -> bytes:
        return struct.pack("!HH", self.grease_extension, 0)
    
    def _build_sni_extension(self) -> bytes:
        sni_bytes = self.sni_domain.encode('ascii')
        sni_name = struct.pack("!BH", 0x00, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_name)) + sni_name
        extension = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        return extension
    
    def _build_extended_master_secret_extension(self) -> bytes:
        return struct.pack("!HH", 0x0017, 0)
    
    def _build_renegotiation_info_extension(self) -> bytes:
        return struct.pack("!HHB", 0xff01, 1, 0)
    
    def _build_supported_groups_extension(self) -> bytes:
        groups = [
            self.grease_group,
            0x001d,
            0x0017,
            0x001e,
            0x0019,
            0x0018,
            0x0100,
            0x0101,
            0x0102,
        ]
        groups_data = b''.join(struct.pack("!H", g) for g in groups)
        return struct.pack("!HHH", 0x000a, len(groups_data) + 2, len(groups_data)) + groups_data
    
    def _build_ec_point_formats_extension(self) -> bytes:
        formats = b'\x01\x00'
        return struct.pack("!HHB", 0x000b, len(formats) + 1, len(formats)) + formats
    
    def _build_session_ticket_extension(self) -> bytes:
        return struct.pack("!HH", 0x0023, 0)
    
    def _build_alpn_extension(self) -> bytes:
        protocols = self.profile['alpn']
        alpn_list = b''.join(struct.pack("!B", len(p)) + p for p in protocols)
        return struct.pack("!HHH", 0x0010, len(alpn_list) + 2, len(alpn_list)) + alpn_list
    
    def _build_status_request_extension(self) -> bytes:
        payload = struct.pack("!BHH", 1, 0, 0)
        return struct.pack("!HH", 0x0005, len(payload)) + payload
    
    def _build_signature_algorithms_extension(self) -> bytes:
        algorithms = [
            0x0403,
            0x0804,
            0x0401,
            0x0503,
            0x0805,
            0x0501,
            0x0806,
            0x0601,
            0x0203,
            0x0201,
        ]
        algs_data = b''.join(struct.pack("!H", a) for a in algorithms)
        return struct.pack("!HHH", 0x000d, len(algs_data) + 2, len(algs_data)) + algs_data
    
    def _build_signed_certificate_timestamp_extension(self) -> bytes:
        return struct.pack("!HH", 0x0012, 0)
    
    def _build_key_share_extension(self) -> bytes:
        key_exchange = os.urandom(32)
        key_share = struct.pack("!HH", 0x001d, len(key_exchange)) + key_exchange
        key_shares = struct.pack("!H", len(key_share)) + key_share
        return struct.pack("!HH", 0x0033, len(key_shares)) + key_shares
    
    def _build_psk_key_exchange_modes_extension(self) -> bytes:
        modes = b'\x01\x01'
        return struct.pack("!HHB", 0x002d, len(modes), len(modes) - 1) + modes[1:]
    
    def _build_supported_versions_extension(self) -> bytes:
        versions = [
            self.grease_version,
            self.TLS_VERSION_TLS13,
            self.TLS_VERSION_TLS12,
            self.TLS_VERSION_TLS11,
            self.TLS_VERSION_TLS10,
        ]
        versions_data = b''.join(struct.pack("!H", v) for v in versions)
        return struct.pack("!HHB", 0x002b, len(versions_data) + 1, len(versions_data)) + versions_data
    
    def _build_compress_certificate_extension(self) -> bytes:
        algorithms = b'\x02\x02\x00'
        return struct.pack("!HHB", 0x001b, len(algorithms), len(algorithms) - 1) + algorithms[1:]
    
    def _build_application_settings_extension(self) -> bytes:
        settings = b'\x00\x02h2\x00\x00'
        return struct.pack("!HH", 0x4469, len(settings)) + settings
    
    def _build_delegated_credentials_extension(self) -> bytes:
        algs = struct.pack("!HHH", 0x0403, 0x0804, 0x0401)
        return struct.pack("!HHH", 0x0022, len(algs) + 2, len(algs)) + algs
    
    def _build_record_size_limit_extension(self) -> bytes:
        limit = 16385
        return struct.pack("!HHH", 0x001c, 2, limit)
    
    def _build_padding_extension(self, target_size: int = 512) -> bytes:
        padding_len = max(0, target_size - 200)
        if padding_len > 0:
            padding = b'\x00' * padding_len
            return struct.pack("!HH", 0x0015, len(padding)) + padding
        return b''
    
    def _build_extensions(self, include_padding: bool = True) -> bytes:
        extensions = b''
        ext_list = self.profile['extensions']
        
        for ext_name in ext_list:
            if ext_name == 'grease':
                extensions += self._build_grease_extension()
            elif ext_name == 'sni':
                extensions += self._build_sni_extension()
            elif ext_name == 'extended_master_secret':
                extensions += self._build_extended_master_secret_extension()
            elif ext_name == 'renegotiation_info':
                extensions += self._build_renegotiation_info_extension()
            elif ext_name == 'supported_groups':
                extensions += self._build_supported_groups_extension()
            elif ext_name == 'ec_point_formats':
                extensions += self._build_ec_point_formats_extension()
            elif ext_name == 'session_ticket':
                extensions += self._build_session_ticket_extension()
            elif ext_name == 'application_layer_protocol_negotiation':
                extensions += self._build_alpn_extension()
            elif ext_name == 'status_request':
                extensions += self._build_status_request_extension()
            elif ext_name == 'signature_algorithms':
                extensions += self._build_signature_algorithms_extension()
            elif ext_name == 'signed_certificate_timestamp':
                extensions += self._build_signed_certificate_timestamp_extension()
            elif ext_name == 'key_share':
                if self.protocol_version >= self.TLS_VERSION_TLS12:
                    extensions += self._build_key_share_extension()
            elif ext_name == 'psk_key_exchange_modes':
                if self.protocol_version == self.TLS_VERSION_TLS13:
                    extensions += self._build_psk_key_exchange_modes_extension()
            elif ext_name == 'supported_versions':
                if self.protocol_version >= self.TLS_VERSION_TLS12:
                    extensions += self._build_supported_versions_extension()
            elif ext_name == 'compress_certificate':
                if self.browser == 'chrome':
                    extensions += self._build_compress_certificate_extension()
            elif ext_name == 'application_settings':
                if self.browser == 'chrome':
                    extensions += self._build_application_settings_extension()
            elif ext_name == 'delegated_credentials':
                if self.browser == 'firefox':
                    extensions += self._build_delegated_credentials_extension()
            elif ext_name == 'record_size_limit':
                if self.browser == 'firefox':
                    extensions += self._build_record_size_limit_extension()
            elif ext_name == 'padding' and include_padding:
                pass
        
        if include_padding and 'padding' in ext_list:
            current_size = len(extensions) + 200
            if current_size < 512 and self.browser == 'chrome':
                extensions += self._build_padding_extension(512)
        
        return extensions
    
    def generate_client_hello(self) -> bytes:
        client_random = self.client_random
        
        session_id = self.session_id if random.random() > 0.3 else b''
        
        cipher_suites = [self.grease_cipher] + self.profile['ciphers']
        cipher_suites_data = b''.join(struct.pack("!H", cs) for cs in cipher_suites)
        
        compression_methods = b'\x01\x00'
        
        extensions = self._build_extensions(include_padding=True)
        extensions_len = len(extensions)
        
        legacy_version = self.TLS_VERSION_TLS12 if self.protocol_version == self.TLS_VERSION_TLS13 else self.protocol_version
        
        handshake_body = (
            struct.pack("!H", legacy_version) +
            client_random +
            struct.pack("!B", len(session_id)) + session_id +
            struct.pack("!H", len(cipher_suites_data)) + cipher_suites_data +
            compression_methods +
            struct.pack("!H", extensions_len) + extensions
        )
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_CLIENT_HELLO) +
            struct.pack("!I", len(handshake_body))[1:] +
            handshake_body
        )
        
        record_version = self.TLS_VERSION_TLS10
        tls_record = (
            struct.pack("!B", self.CONTENT_TYPE_HANDSHAKE) +
            struct.pack("!H", record_version) +
            struct.pack("!H", len(handshake_msg)) +
            handshake_msg
        )
        
        return tls_record
    
    def generate_server_hello(self) -> bytes:
        server_random = self.server_random
        
        session_id = self.session_id if random.random() > 0.5 else os.urandom(32)
        
        chosen_cipher = 0x1301
        
        compression_method = b'\x00'
        
        extensions = b''
        
        if self.protocol_version == self.TLS_VERSION_TLS13:
            extensions += struct.pack("!HHH", 0x002b, 2, self.TLS_VERSION_TLS13)
            
            key_exchange = os.urandom(32)
            key_share = struct.pack("!HH", 0x001d, len(key_exchange)) + key_exchange
            extensions += struct.pack("!HH", 0x0033, len(key_share)) + key_share
        
        extensions += struct.pack("!HH", 0x0017, 0)
        
        extensions += struct.pack("!HHB", 0xff01, 1, 0)
        
        if self.profile['alpn']:
            alpn = self.profile['alpn'][0]
            alpn_data = struct.pack("!B", len(alpn)) + alpn
            extensions += struct.pack("!HHH", 0x0010, len(alpn_data) + 2, len(alpn_data)) + alpn_data
        
        extensions_len = len(extensions)
        
        legacy_version = self.TLS_VERSION_TLS12 if self.protocol_version == self.TLS_VERSION_TLS13 else self.protocol_version
        
        handshake_body = (
            struct.pack("!H", legacy_version) +
            server_random +
            struct.pack("!B", len(session_id)) + session_id +
            struct.pack("!H", chosen_cipher) +
            compression_method
        )
        
        if extensions_len > 0:
            handshake_body += struct.pack("!H", extensions_len) + extensions
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_SERVER_HELLO) +
            struct.pack("!I", len(handshake_body))[1:] +
            handshake_body
        )
        
        record_version = self.TLS_VERSION_TLS12
        tls_record = (
            struct.pack("!B", self.CONTENT_TYPE_HANDSHAKE) +
            struct.pack("!H", record_version) +
            struct.pack("!H", len(handshake_msg)) +
            handshake_msg
        )
        
        return tls_record
    
    def generate_change_cipher_spec(self) -> bytes:
        ccs_payload = b'\x01'
        
        record_version = self.TLS_VERSION_TLS12
        tls_record = (
            struct.pack("!B", self.CONTENT_TYPE_CHANGE_CIPHER_SPEC) +
            struct.pack("!H", record_version) +
            struct.pack("!H", len(ccs_payload)) +
            ccs_payload
        )
        
        return tls_record
    
    def generate_encrypted_extensions(self) -> bytes:
        if self.protocol_version != self.TLS_VERSION_TLS13:
            return b''
        
        extensions = b''
        
        handshake_body = struct.pack("!H", len(extensions)) + extensions
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS) +
            struct.pack("!I", len(handshake_body))[1:] +
            handshake_body
        )
        
        return self.wrap_application_data(handshake_msg)
    
    def generate_fake_certificate(self) -> bytes:
        
        fake_cert_data = os.urandom(random.randint(800, 1500))
        
        handshake_body = (
            struct.pack("!I", len(fake_cert_data))[1:] +
            fake_cert_data
        )
        
        if self.protocol_version == self.TLS_VERSION_TLS13:
            handshake_body = b'\x00' + handshake_body
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_CERTIFICATE) +
            struct.pack("!I", len(handshake_body))[1:] +
            handshake_body
        )
        
        return self.wrap_application_data(handshake_msg)
    
    def generate_certificate_verify(self) -> bytes:
        fake_signature = os.urandom(64)
        
        handshake_body = (
            struct.pack("!H", 0x0403) +
            struct.pack("!H", len(fake_signature)) +
            fake_signature
        )
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_CERTIFICATE_VERIFY) +
            struct.pack("!I", len(handshake_body))[1:] +
            handshake_body
        )
        
        return self.wrap_application_data(handshake_msg)
    
    def generate_finished(self) -> bytes:
        verify_data = os.urandom(32)
        
        handshake_msg = (
            struct.pack("!B", self.HANDSHAKE_TYPE_FINISHED) +
            struct.pack("!I", len(verify_data))[1:] +
            verify_data
        )
        
        return self.wrap_application_data(handshake_msg)
    
    def generate_complete_server_handshake(self) -> bytes:
        messages = b''
        
        messages += self.generate_server_hello()
        
        if self.protocol_version == self.TLS_VERSION_TLS13:
            messages += self.generate_change_cipher_spec()
            messages += self.generate_encrypted_extensions()
            messages += self.generate_fake_certificate()
            messages += self.generate_certificate_verify()
            messages += self.generate_finished()
        else:
            messages += self.generate_fake_certificate()
            messages += self.generate_change_cipher_spec()
            messages += self.generate_finished()
        
        return messages
    
    def wrap_application_data(self, data: bytes) -> bytes:
        if len(data) <= 1024:
            max_fragment = len(data)
        else:
            max_fragment = random.choice(self.record_size_distribution)
        
        result = b''
        offset = 0
        
        while offset < len(data):
            chunk_size = min(max_fragment, len(data) - offset)
            chunk = data[offset:offset + chunk_size]
            
            record_version = self.TLS_VERSION_TLS12
            tls_record = (
                struct.pack("!B", self.CONTENT_TYPE_APPLICATION_DATA) +
                struct.pack("!H", record_version) +
                struct.pack("!H", len(chunk)) +
                chunk
            )
            result += tls_record
            offset += chunk_size
            
            if len(data) - offset > 1024:
                max_fragment = random.choice(self.record_size_distribution)
        
        self.sent_records += 1
        return result
    
    def wrap_application_data_with_padding(self, data: bytes) -> bytes:
        if random.random() < 0.3:
            padding_len = random.randint(1, 64)
            padded = struct.pack("!B", padding_len) + os.urandom(padding_len) + data
            return self.wrap_application_data(padded)
        else:
            return self.wrap_application_data(b'\x00' + data)
    
    def unwrap_application_data(self, data: bytes) -> bytes:
        result = b''
        offset = 0
        
        while offset < len(data):
            if len(data) - offset < 5:
                break
            
            content_type = data[offset]
            record_version = struct.unpack("!H", data[offset + 1:offset + 3])[0]
            fragment_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
            
            if content_type != self.CONTENT_TYPE_APPLICATION_DATA:
                raise ValueError("Invalid record type")
            
            if len(data) - offset < 5 + fragment_len:
                raise ValueError("Incomplete record")
            
            fragment = data[offset + 5:offset + 5 + fragment_len]
            result += fragment
            offset += 5 + fragment_len
        
        self.recv_records += 1
        return result
    
    def unwrap_application_data_with_padding(self, data: bytes) -> bytes:
        unwrapped = self.unwrap_application_data(data)
        
        if len(unwrapped) < 1:
            return b''
        
        padding_len = unwrapped[0]
        if padding_len > 0:
            if len(unwrapped) < 1 + padding_len:
                raise ValueError("Invalid padding")
            return unwrapped[1 + padding_len:]
        else:
            return unwrapped[1:]
    
    @staticmethod
    def detect_tls_client_hello(data: bytes) -> Optional[str]:
        try:
            if len(data) < 6:
                return None
            
            content_type = data[0]
            if content_type != TlsCamouflage.CONTENT_TYPE_HANDSHAKE:
                return None
            
            if len(data) < 43:
                return None
            
            handshake_type = data[5]
            if handshake_type != TlsCamouflage.HANDSHAKE_TYPE_CLIENT_HELLO:
                return None
            
            offset = 5
            offset += 1
            offset += 3
            offset += 2
            offset += 32
            
            if offset >= len(data):
                return None
            
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            if offset + 2 >= len(data):
                return None
            
            cipher_suites_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len
            
            if offset + 1 >= len(data):
                return None
            
            compression_len = data[offset]
            offset += 1 + compression_len
            
            if offset + 2 >= len(data):
                return None
            
            extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            
            ext_end = offset + extensions_len
            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                offset += 4
                
                if ext_type == 0x0000:
                    if offset + 2 <= len(data):
                        list_len = struct.unpack("!H", data[offset:offset + 2])[0]
                        offset += 2
                        if offset + 3 <= len(data):
                            name_type = data[offset]
                            name_len = struct.unpack("!H", data[offset + 1:offset + 3])[0]
                            offset += 3
                            if name_type == 0 and offset + name_len <= len(data):
                                sni = data[offset:offset + name_len].decode('ascii', errors='ignore')
                                return sni
                
                offset += ext_len
            
            return None
            
        except Exception:
            return None
    
    async def simulate_realistic_timing(self):
        jitter = random.randint(*self.timing_jitter_ms) / 1000.0
        await asyncio.sleep(jitter)

class SessionCrypto:
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
            if self.tx_nonce >= (2**64 - 1):
                raise ValueError("Nonce overflow - session must be renegotiated")
            nonce = struct.pack("!Q", self.tx_nonce).rjust(12, b'\x00')
            self.tx_nonce += 1
            return self.tx_cipher.encrypt(nonce, data, None)

    async def decrypt(self, data: bytes) -> bytes:
        async with self.rx_lock:
            if self.rx_nonce >= (2**64 - 1):
                raise ValueError("Nonce overflow - session must be renegotiated")
            nonce = struct.pack("!Q", self.rx_nonce).rjust(12, b'\x00')
            self.rx_nonce += 1
            return self.rx_cipher.decrypt(nonce, data, None)

class SecureSocket:
    def __init__(self, reader, writer, crypto):
        self.r = reader
        self.w = writer
        self.c = crypto
        self.obf = Obfuscator()
        self._closed = False
        self.last_activity = time.time()
        self.peer_addr = None
        
        self.tls_camouflage = None
        if SNI_DOMAIN:
            browser = random.choice(list(TlsCamouflage.BROWSER_PROFILES.keys()))
            self.tls_camouflage = TlsCamouflage(SNI_DOMAIN, version="1.3", browser=browser)
        
        try:
            self.peer_addr = writer.get_extra_info('peername')
        except:
            self.peer_addr = "unknown"
        
        sock = writer.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception as e:
                log.debug(f"Failed to set socket options: {e}")

    async def send_frame(self, data: bytes):
        if self._closed: return
        try:
            dlen = len(data)
            pad_len = random.randint(0, MAX_PADDING)
            padding = os.urandom(pad_len)
            
            payload = struct.pack("!H", dlen) + data + padding
            encrypted = await self.c.encrypt(payload)
            
            frame = struct.pack("!H", len(encrypted)) + encrypted
            
            if self.tls_camouflage and self.tls_camouflage.handshake_complete:
                frame = self.tls_camouflage.wrap_application_data_with_padding(frame)
            
            self.w.write(frame)
            await self.w.drain()
            self.last_activity = time.time()
            
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
        while not self._closed:
            try:
                if self.tls_camouflage and self.tls_camouflage.handshake_complete:
                    tls_head = await self.r.readexactly(5)
                    content_type = tls_head[0]
                    tls_len = struct.unpack("!H", tls_head[3:5])[0]
                    
                    if tls_len > MAX_FRAME_SIZE:
                        log.error(f"Oversized TLS record ({tls_len} bytes) from {self.peer_addr}")
                        await metrics.record_error("oversized_tls_record")
                        raise ValueError(f"TLS record size {tls_len} exceeds maximum")
                    
                    tls_body = await self.r.readexactly(tls_len)
                    tls_data = tls_head + tls_body
                    
                    unwrapped = self.tls_camouflage.unwrap_application_data_with_padding(tls_data)
                    
                    if len(unwrapped) < 2:
                        await self.close()
                        return None
                    
                    cipher_len = struct.unpack("!H", unwrapped[:2])[0]
                    ciphertext = unwrapped[2:2+cipher_len]
                else:
                    try:
                        async with asyncio.timeout(CONNECTION_TIMEOUT):
                            head = await self.r.readexactly(2)
                    except asyncio.TimeoutError:
                        log.warning(f"Read timeout from {self.peer_addr}")
                        await metrics.record_error("read_timeout")
                        await self.close()
                        return None
                    
                    cipher_len = struct.unpack("!H", head)[0]
                    
                    if cipher_len > MAX_FRAME_SIZE:
                        log.error(f"Oversized frame ({cipher_len} bytes) from {self.peer_addr}")
                        await metrics.record_error("oversized_frame")
                        raise ValueError(f"Frame size {cipher_len} exceeds maximum {MAX_FRAME_SIZE}")

                    try:
                        async with asyncio.timeout(CONNECTION_TIMEOUT):
                            ciphertext = await self.r.readexactly(cipher_len)
                    except asyncio.TimeoutError:
                        log.warning(f"Read timeout waiting for frame body from {self.peer_addr}")
                        await metrics.record_error("read_timeout")
                        await self.close()
                        return None
                
                try:
                    plaintext = await self.c.decrypt(ciphertext)
                except Exception as e:
                    log.warning(f"Decryption failed from {self.peer_addr}: {e}")
                    await metrics.record_error("decryption_failed")
                    await self.close()
                    return None
                
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
                
                await metrics.record_frame(sent=False)
                await metrics.record_data(bytes_recv=cipher_len)
                self.last_activity = time.time()
                
                if len(data) == 1 and data[0] == 0x02:
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
        try:
            if self.tls_camouflage:
                client_hello = self.tls_camouflage.generate_client_hello()
                self.w.write(client_hello)
                await self.w.drain()
                
                await self.tls_camouflage.simulate_realistic_timing()
                
                server_hello_head = await self.r.readexactly(5)
                server_hello_len = struct.unpack("!H", server_hello_head[3:5])[0]
                server_hello_body = await self.r.readexactly(server_hello_len)
                
                log.debug(f"TLS handshake initiated with SNI: {self.tls_camouflage.sni_domain}")
            
            my_pub = self.c.get_pub_bytes()
            entropy = os.urandom(random.randint(16, 64))
            raw = bytes([len(entropy)]) + entropy + my_pub
            masked = self.obf.mask(raw)
            
            self.w.write(struct.pack("!H", len(masked)) + masked)
            await self.w.drain()
            
            plen = struct.unpack("!H", await self.r.readexactly(2))[0]
            peer_masked = await self.r.readexactly(plen)
            peer_raw = self.obf.unmask(peer_masked)
            
            e_len = peer_raw[0]
            peer_pub = peer_raw[1+e_len : 1+e_len+32]
            
            self.c.derive(peer_pub, True)
            
            ts = int(time.time())
            proof = hashlib.sha256(NETWORK_SECRET.encode() + struct.pack("!Q", ts)).digest()
            await self.send_frame(struct.pack("!Q", ts) + proof)
            
            if self.tls_camouflage:
                self.tls_camouflage.handshake_complete = True
                log.info(f"TLS camouflage active for {self.peer_addr} (SNI: {self.tls_camouflage.sni_domain})")
            
            return True
        except Exception as e:
            log.warning(f"Handshake Init Failed: {e}")
            await self.close()
            return False

    async def handshake_resp(self) -> bool:
        try:
            first_byte = await self.r.readexactly(1)
            
            if first_byte[0] == 0x16:
                remaining_header = await self.r.readexactly(4)
                tls_header = first_byte + remaining_header
                
                tls_len = struct.unpack("!H", tls_header[3:5])[0]
                
                if tls_len > MAX_FRAME_SIZE:
                    log.error(f"Oversized TLS handshake ({tls_len} bytes)")
                    await metrics.record_error("oversized_tls_handshake")
                    raise ValueError(f"TLS handshake size {tls_len} exceeds maximum")
                
                tls_body = await self.r.readexactly(tls_len)
                client_hello = tls_header + tls_body
                
                detected_sni = TlsCamouflage.detect_tls_client_hello(client_hello)
                if detected_sni:
                    if not self.tls_camouflage:
                        self.tls_camouflage = TlsCamouflage(detected_sni, version="1.3", browser="chrome")
                    
                    server_handshake = self.tls_camouflage.generate_complete_server_handshake()
                    self.w.write(server_handshake)
                    await self.w.drain()
                    
                    log.debug(f"TLS handshake detected with SNI: {detected_sni}")
                    
                    await self.tls_camouflage.simulate_realistic_timing()
                
                plen = struct.unpack("!H", await self.r.readexactly(2))[0]
                if plen > 1024: raise ValueError("Hello too big")
                peer_masked = await self.r.readexactly(plen)
            else:
                second_byte = await self.r.readexactly(1)
                plen = struct.unpack("!H", first_byte + second_byte)[0]
                if plen > 1024: raise ValueError("Hello too big")
                peer_masked = await self.r.readexactly(plen)
            
            peer_raw = self.obf.unmask(peer_masked)
            
            e_len = peer_raw[0]
            peer_pub = peer_raw[1+e_len : 1+e_len+32]
            
            my_pub = self.c.get_pub_bytes()
            entropy = os.urandom(random.randint(16, 64))
            raw = bytes([len(entropy)]) + entropy + my_pub
            masked = self.obf.mask(raw)
            
            self.w.write(struct.pack("!H", len(masked)) + masked)
            await self.w.drain()
            
            self.c.derive(peer_pub, False)
            
            auth_frame = await self.recv_frame()
            if not auth_frame: return False
            
            if len(auth_frame) < 40:
                log.warning(f"Auth Failed: Invalid frame length from {self.peer_addr}")
                await metrics.record_error("auth_invalid_frame")
                return False
            
            ts = struct.unpack("!Q", auth_frame[:8])[0]
            proof = auth_frame[8:]
            
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
            
            if self.tls_camouflage:
                self.tls_camouflage.handshake_complete = True
                log.info(f"TLS camouflage active for {self.peer_addr} (SNI: {self.tls_camouflage.sni_domain})")
            
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
        if self._closed: return
        self._closed = True
        try:
            await metrics.record_disconnect()
            self.w.close()
            await self.w.wait_closed()
        except: pass

class PeerManager:
    def __init__(self, port):
        self.my_port = port
        self.peers: Dict[str, Dict] = {} 
        self.lock = asyncio.Lock()
        self.my_external_ip: Optional[str] = None
        self.am_i_exit = False
        self.bunker_mode = False

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
            self.peers[ip] = {
                'ts': time.time(),
                'exit': is_exit,
                'port': port
            }

    async def get_best_exit(self) -> Optional[Tuple[str, int]]:
        async with self.lock:
            now = time.time()
            candidates = [
                (ip, d['port']) for ip, d in self.peers.items()
                if d['exit'] and (now - d['ts'] < 300)
            ]
            if not candidates: 
                candidates = [
                    (ip, d['port']) for ip, d in self.peers.items() 
                    if d['exit']
                ]
            
            if not candidates: return None
            return random.choice(candidates)

    def get_sync_list(self) -> List[Dict]:
        active = [
            {'ip': k, 'port': v['port'], 'exit': v['exit']}
            for k, v in self.peers.items()
            if time.time() - v['ts'] < 3600
        ]
        return random.sample(active, min(len(active), 20))

    async def cleanup(self):
        async with self.lock:
            now = time.time()
            dead = [k for k, v in self.peers.items() if now - v['ts'] > 3600]
            for k in dead: del self.peers[k]

class StunClient:
    async def get_ip(self) -> Optional[str]:
        for server, port in STUN_SERVERS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                txn = os.urandom(12)
                req = b'\x00\x01\x00\x00\x21\x12\xA4\x42' + txn
                sock.sendto(req, (server, port))
                
                resp, _ = sock.recvfrom(2048)
                
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
                    
                    if atype == 0x0001:
                        if idx + alen > len(resp):
                            break
                        family = resp[idx+1]
                        if family == 0x01:
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

class HydraNode:
    def __init__(self):
        self.port = self._get_port()
        self.peers = PeerManager(self.port)
        self.stun = StunClient()
        self.running = True
        self.shutdown_event = asyncio.Event()
        
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._shutdown(s)))
        except NotImplementedError:
            pass
        except Exception as e:
            log.debug(f"Could not setup signal handlers: {e}")
    
    async def _shutdown(self, sig):
        log.info(f"\n\033[93m[SHUTDOWN] Received signal {sig}, initiating graceful shutdown...\033[0m")
        self.running = False
        self.shutdown_event.set()
        
        metrics.log_stats()

    def _get_port(self):
        if PORT_OVERRIDE > 0: return PORT_OVERRIDE
        h = hashlib.sha256(NETWORK_SECRET.encode()).digest()
        return HYDRA_PORT_BASE + (int.from_bytes(h[:2], 'big') % 5000)

    async def start(self):
        print(f"\033[96m[HYDRA v7] Starting on 0.0.0.0:{self.port}...\033[0m")
        print(f"Secret Hash: {hashlib.sha256(NETWORK_SECRET.encode()).hexdigest()[:8]}")
        
        log.info(f"Configuration: Max Connections={MAX_CONCURRENT_CONNECTIONS}, "
                f"Timeout={CONNECTION_TIMEOUT}s, Timestamp Window={TIMESTAMP_WINDOW}s")

        try:
            srv = await asyncio.start_server(self.handle_tunnel, '0.0.0.0', self.port)
            socks = await asyncio.start_server(self.handle_socks, '127.0.0.1', SOCKS_PORT)
            log.info(f"HYDRA tunnel listening on 0.0.0.0:{self.port}")
            log.info(f"SOCKS5 proxy listening on 127.0.0.1:{SOCKS_PORT}")
        except OSError as e:
            log.error(f"Port bind failed: {e}")
            print(f"\033[91m[ERROR] Port bind failed: {e}\033[0m")
            return

        my_ip = await self.stun.get_ip()
        if my_ip:
            log.info(f"Public IP: {my_ip}")
            self.peers.my_external_ip = my_ip
        else:
            log.warning("STUN Failed. Entering Bunker Mode (Hidden Node).")
            self.peers.bunker_mode = True

        tasks = [
            self.run_server(srv),
            self.run_server(socks),
            self.task_connectivity_check(),
            self.task_pex(),
            self.task_cleanup(),
            self.task_stats_logger(),
        ]

        log.info("\033[92m[READY] Node initialized and ready to serve\033[0m")

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            log.info("\nReceived interrupt, shutting down...")
            self.running = False
        finally:
            log.info("Node stopped")
            metrics.log_stats()

    async def run_server(self, srv):
        async with srv:
            try:
                await srv.serve_forever()
            except asyncio.CancelledError:
                log.debug("Server task cancelled")

    async def task_stats_logger(self):
        while self.running:
            await asyncio.sleep(60)
            if self.running:
                metrics.log_stats()
    
    async def task_connectivity_check(self):
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
            
            if success and not self.peers.am_i_exit:
                log.info("\033[92m[ROLE] Promoted to EXIT NODE\033[0m")
            elif not success and self.peers.am_i_exit:
                log.warning("\033[93m[ROLE] Demoted to RELAY NODE\033[0m")
            
            self.peers.am_i_exit = success
            await asyncio.sleep(60)

    async def task_pex(self):
        while self.running:
            target = await self.peers.get_best_exit()
            if not target:
                for s in SEEDS:
                    if ":" in s:
                        ip, p = s.split(":")
                        asyncio.create_task(self.do_pex(ip, int(p)))
                await asyncio.sleep(10)
                continue

            ip, port = target
            asyncio.create_task(self.do_pex(ip, port))
            await asyncio.sleep(30)

    async def task_cleanup(self):
        while self.running:
            await asyncio.sleep(300)
            await self.peers.cleanup()

    async def do_pex(self, ip, port):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
            ss = SecureSocket(r, w, SessionCrypto())
            if not await ss.handshake_init(): return
            
            my_list = self.peers.get_sync_list()
            if not self.peers.bunker_mode and self.peers.my_external_ip:
                my_list.append({
                    'ip': self.peers.my_external_ip,
                    'port': self.port,
                    'exit': self.peers.am_i_exit
                })
            
            data = json.dumps(my_list).encode()
            await ss.send_frame(b'\x99' + data)
            
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
        except: pass

    async def handle_tunnel(self, r, w):
        ss = SecureSocket(r, w, SessionCrypto())
        try:
            if not await ss.handshake_resp(): return
            
            while True:
                frame = await ss.recv_frame()
                if not frame: break
                
                cmd = frame[0]
                
                if cmd == 0x01:
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
                    break
                
                elif cmd == 0x99:
                    self.process_pex_blob(frame[1:])
                    my_list = self.peers.get_sync_list()
                    if not self.peers.bunker_mode and self.peers.my_external_ip:
                        my_list.append({
                            'ip': self.peers.my_external_ip,
                            'port': self.port,
                            'exit': self.peers.am_i_exit
                        })
                    rep = json.dumps(my_list).encode()
                    await ss.send_frame(b'\x99' + rep)
                    break
                    
        except Exception:
            await ss.close()

    async def run_exit(self, client_ss, host, port):
        target_w = None
        try:
            target_r, target_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), CONNECTION_TIMEOUT
            )
            await client_ss.send_frame(b'\x00')
            
            await self.pipe_secure_plain(client_ss, target_r, target_w)
            
        except Exception:
            await client_ss.send_frame(b'\xFF')
            if target_w:
                target_w.close()
                await target_w.wait_closed()

    async def run_relay(self, client_ss, init_packet):
        for _ in range(3):
            exit_node = await self.peers.get_best_exit()
            if not exit_node: break
            
            ip, port = exit_node
            next_ss = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECTION_TIMEOUT)
                next_ss = SecureSocket(r, w, SessionCrypto())
                if not await next_ss.handshake_init(): raise Exception()
                
                await next_ss.send_frame(init_packet)
                
                resp = await next_ss.recv_frame()
                if not resp or resp != b'\x00': raise Exception()
                
                await client_ss.send_frame(b'\x00')
                
                await self.bridge_secure(client_ss, next_ss)
                return
                
            except Exception:
                if next_ss: await next_ss.close()
                continue
        
        await client_ss.send_frame(b'\xFF')

    async def handle_socks(self, r, w):
        try:
            ver = await r.read(1)
            if ver != b'\x05':
                w.close()
                await w.wait_closed()
                return
            nm = (await r.read(1))[0]
            await r.read(nm)
            w.write(b'\x05\x00'); await w.drain()
            
            head = await r.readexactly(4)
            cmd = head[1]
            if cmd != 1:
                w.close()
                await w.wait_closed()
                return
            
            atyp = head[3]
            if atyp == 1:
                addr = socket.inet_ntoa(await r.readexactly(4))
            elif atyp == 3:
                l = (await r.readexactly(1))[0]
                addr = (await r.readexactly(l)).decode()
            else:
                w.close()
                await w.wait_closed()
                return
            
            port = struct.unpack("!H", await r.readexactly(2))[0]
            
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
        for _ in range(2):
            exit_node = await self.peers.get_best_exit()
            if not exit_node: break
            
            ss = None
            try:
                ip, p = exit_node
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), CONNECTION_TIMEOUT)
                ss = SecureSocket(r, w, SessionCrypto())
                if not await ss.handshake_init(): raise Exception()
                
                payload = b'\x01' + bytes([len(host)]) + host.encode() + struct.pack("!H", port)
                await ss.send_frame(payload)
                
                res = await ss.recv_frame()
                if res != b'\x00': raise Exception()
                
                cw.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'); await cw.drain()
                await self.pipe_secure_plain(ss, cr, cw)
                return
            except:
                if ss: await ss.close()
        
        try:
            cw.close()
            await cw.wait_closed()
        except:
            pass

    async def keepalive_sender(self, ss: SecureSocket):
        while not ss._closed:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if time.time() - ss.last_activity > KEEPALIVE_INTERVAL:
                try: await ss.send_heartbeat()
                except: break

    async def pipe_plain(self, r1, w1, r2, w2):
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

        await asyncio.gather(s2p(), p2s())
        ka.cancel()
        await ss.close()

    async def bridge_secure(self, s1: SecureSocket, s2: SecureSocket):
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

if __name__ == "__main__":
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