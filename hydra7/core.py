import asyncio
import socket
import struct
import os
import hashlib
import json
import random
import time
import sys
from typing import Optional, Dict, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SECRET = os.getenv("HYDRA_SECRET", "Proprietary_Mesh_Key_V7_Genius")
PORT = int(os.getenv("HYDRA_PORT", 0))
SEEDS = [s.strip() for s in os.getenv("HYDRA_SEEDS", "").split(",") if s.strip()]
DOMAINS = ["yandex.ru", "sberbank.ru", "gosuslugi.ru", "max.ru", "vk.com"]
SOCKS_PORT = 1080
BASE_PORT = 25000
BUF = 16384

class GhostReflector:
    @staticmethod
    def get_headers(domain):
        return (f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: YandexBrowser/23.9.1.962\r\n"
                f"Accept: text/html,application/xhtml+xml\r\nConnection: keep-alive\r\n\r\n").encode()

class DpiEngine:
    @staticmethod
    async def desync_write(writer, data: bytes):
        if len(data) > 5:
            writer.write(data[:random.randint(1, 3)])
            await writer.drain()
            await asyncio.sleep(0.005)
            writer.write(data[3:])
        else:
            writer.write(data)
        await writer.drain()

class CryptoSession:
    def __init__(self):
        self.priv = x25519.X25519PrivateKey.generate()
        self.tx = None
        self.rx = None
        self.tn = 0
        self.rn = 0

    def setup(self, p_bytes, init):
        sh = self.priv.exchange(x25519.X25519PublicKey.from_public_bytes(p_bytes))
        k = HKDF(hashes.SHA256(), 64, hashlib.sha256(SECRET.encode()).digest(), b'H7_GHOST').derive(sh)
        self.tx = ChaCha20Poly1305(k[:32] if init else k[32:])
        self.rx = ChaCha20Poly1305(k[32:] if init else k[:32])

    def seal(self, d):
        n = struct.pack("!Q", self.tn).rjust(12, b'\x00')
        self.tn += 1
        return self.tx.encrypt(n, d, None)

    def open(self, d):
        n = struct.pack("!Q", self.rn).rjust(12, b'\x00')
        self.rn += 1
        return self.rx.decrypt(n, d, None)

class SecureSocket:
    def __init__(self, r, w, c):
        self.r, self.w, self.c = r, w, c
        self.closed = False
        self.domain = random.choice(DOMAINS)
        s = w.get_extra_info('socket')
        if s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF)

    async def send(self, d):
        try:
            p = struct.pack("!H", len(d)) + d + os.urandom(random.randint(8, 64))
            enc = self.c.seal(p)
            f = b"\x17\x03\x03" + struct.pack("!H", len(enc)) + enc
            await DpiEngine.desync_write(self.w, f)
        except: await self.close()

    async def recv(self):
        try:
            h = await self.r.readexactly(5)
            d = await self.r.readexactly(struct.unpack("!H", h[3:5])[0])
            p = self.c.open(d)
            return p[2:2+struct.unpack("!H", p[:2])[0]]
        except: return None

    async def handshake(self, init):
        try:
            if init:
                self.w.write(GhostReflector.get_headers(self.domain))
                pub = self.priv_bytes()
                iv = os.urandom(16)
                self.w.write(iv + pub)
                await self.w.drain()
                p_iv = await self.r.readexactly(16)
                p_pub = await self.r.readexactly(32)
                self.c.setup(p_pub, True)
                ts = struct.pack("!Q", int(time.time()))
                await self.send(ts + hashlib.sha256(SECRET.encode() + ts).digest())
            else:
                await self.r.readuntil(b"\r\n\r\n")
                p_iv = await self.r.readexactly(16)
                p_pub = await self.r.readexactly(32)
                iv = os.urandom(16)
                self.w.write(iv + self.priv_bytes())
                await self.w.drain()
                self.c.setup(p_pub, False)
                auth = await self.recv()
                if not auth or auth[8:] != hashlib.sha256(SECRET.encode() + auth[:8]).digest(): return False
            return True
        except: return False

    def priv_bytes(self): return self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    async def close(self):
        if not self.closed:
            self.closed = True
            try: self.w.close(); await self.w.wait_closed()
            except: pass

class PeerManager:
    def __init__(self):
        self.peers = {}
        for s in SEEDS:
            try: h, p = s.split(":"); self.peers[h] = int(p)
            except: pass

    def get_route(self):
        items = list(self.peers.items())
        return random.sample(items, min(len(items), 3))

class HydraNode:
    def __init__(self):
        self.port = PORT or (BASE_PORT + (int.from_bytes(hashlib.sha256(SECRET.encode()).digest()[:2], "big") % 5000))
        self.pm = PeerManager()

    async def start(self):
        srv = await asyncio.start_server(self.tunnel, "0.0.0.0", self.port)
        socks = await asyncio.start_server(self.socks, "127.0.0.1", SOCKS_PORT)
        async with srv, socks: await asyncio.gather(srv.serve_forever(), socks.serve_forever())

    async def tunnel(self, r, w):
        ss = SecureSocket(r, w, CryptoSession())
        if await ss.handshake(False):
            while True:
                f = await ss.recv()
                if not f: break
                if f[0] == 0x01:
                    l = f[1]
                    h, p = f[2:2+l].decode(), struct.unpack("!H", f[2+l:2+l+2])[0]
                    try:
                        tr, tw = await asyncio.wait_for(asyncio.open_connection(h, p), 5)
                        await ss.send(b"\x00")
                        await self.pipe(ss, tr, tw)
                        break
                    except: await ss.send(b"\xff"); break
                elif f[0] == 0x05:
                    l = f[1]
                    nh, np = f[2:2+l].decode(), struct.unpack("!H", f[2+l:2+l+2])[0]
                    try:
                        nr, nw = await asyncio.open_connection(nh, np)
                        ns = SecureSocket(nr, nw, CryptoSession())
                        if await ns.handshake(True):
                            await ns.send(f[2+l+2:])
                            await self.bridge(ss, ns)
                            break
                    except: break
        await ss.close()

    async def socks(self, r, w):
        try:
            await r.read(2)
            w.write(b"\x05\x00"); await w.drain()
            h = await r.readexactly(4)
            if h[3] == 1: addr = socket.inet_ntoa(await r.readexactly(4))
            elif h[3] == 3: addr = (await r.readexactly((await r.readexactly(1))[0])).decode()
            else: return
            port = struct.unpack("!H", await r.readexactly(2))[0]
            route = self.pm.get_route()
            if not route:
                tr, tw = await asyncio.open_connection(addr, port)
                w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await self.raw_pipe(r, w, tr, tw)
            else:
                rh, rp = route[0]
                nr, nw = await asyncio.open_connection(rh, rp)
                ns = SecureSocket(nr, nw, CryptoSession())
                if await ns.handshake(True):
                    p = b"\x01" + bytes([len(addr)]) + addr.encode() + struct.pack("!H", port)
                    for rh_nxt, rp_nxt in route[1:]:
                        p = b"\x05" + bytes([len(rh_nxt)]) + rh_nxt.encode() + struct.pack("!H", rp_nxt) + p
                    await ns.send(p)
                    if (await ns.recv()) == b"\x00":
                        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                        await self.ss_pipe(ns, r, w)
        except: pass

    async def pipe(self, ss, tr, tw):
        async def s2t():
            try:
                while True:
                    d = await ss.recv()
                    if not d: break
                    tw.write(d); await tw.drain()
            except: pass
        async def t2s():
            try:
                while True:
                    d = await tr.read(BUF)
                    if not d: break
                    await ss.send(d)
            except: pass
        await asyncio.gather(s2t(), t2s()); tw.close()

    async def bridge(self, s1, s2):
        async def p(a, b):
            try:
                while True:
                    d = await a.recv()
                    if not d: break
                    await b.send(d)
            except: pass
        await asyncio.gather(p(s1, s2), p(s2, s1))
        await s1.close(); await s2.close()

    async def raw_pipe(self, r1, w1, r2, w2):
        async def p(r, w):
            try:
                while True:
                    d = await r.read(BUF)
                    if not d: break
                    w.write(d); await w.drain()
            except: pass
        await asyncio.gather(p(r1, w2), p(r2, w1))

    async def ss_pipe(self, ss, pr, pw):
        async def s2p():
            try:
                while True:
                    d = await ss.recv()
                    if not d: break
                    pw.write(d); await pw.drain()
            except: pass
        async def p2s():
            try:
                while True:
                    d = await pr.read(BUF)
                    if not d: break
                    await ss.send(d)
            except: pass
        await asyncio.gather(s2p(), p2s()); await ss.close()

if __name__ == "__main__":
    if os.name != "nt":
        try: import uvloop; uvloop.install()
        except: pass
    asyncio.run(HydraNode().start())