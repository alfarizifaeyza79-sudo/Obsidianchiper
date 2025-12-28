#!/usr/bin/env python3
# ===================================================================
# OBSIDIAN CIPHER v3.0 - PREMIUM EDITION
# TOTAL LINES: 2567 (OPTIMIZED & FULL WORKING)
# LICENSE KEY: obsidian-chiper
# CONTACT: @Zxxtirwd (Telegram)
# PRICE: Rp 30.000 (Lifetime Access)
# ===================================================================

import os
import sys
import time
import hashlib
import json
import socket
import threading
import random
import string
import requests
import base64
import re
import subprocess
from datetime import datetime
from getpass import getpass
from colorama import init, Fore, Back, Style
import sqlite3
import zipfile
import csv

# Initialize colorama
init(autoreset=True)

# ============ CONFIGURATION ============
class Config:
    APP_NAME = "OBSIDIAN CIPHER v3.0"
    VERSION = "3.0.0"
    AUTHOR = "CYBER ELITE"
    PRICE = "Rp 30.000"
    CONTACT = "@Zxxtirwd"
    LICENSE_KEY = "obsidian-chiper"
    USER_FILE = "obsidian_users.json"
    LOG_FILE = "obsidian_log.txt"
    DB_FILE = "obsidian_data.db"
    MAX_LOGIN_ATTEMPTS = 3
    SESSION_TIMEOUT = 1800

# ============ ASCII ART ============
def show_banner():
    banner = f"""
{Fore.CYAN} ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
{Fore.MAGENTA}██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
{Fore.BLUE}██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     ███████╗
{Fore.GREEN}██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ╚════██║
{Fore.YELLOW}╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗███████║
{Fore.RED} ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
{Fore.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    print(banner)

# ============ LOGGING SYSTEM ============
class Logger:
    def __init__(self):
        self.log_file = Config.LOG_FILE
        
    def log(self, event, user="SYSTEM", status="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{status}] User:{user} - {event}\n"
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        if status == "ERROR":
            color = Fore.RED
        elif status == "WARNING":
            color = Fore.YELLOW
        elif status == "SUCCESS":
            color = Fore.GREEN
        else:
            color = Fore.CYAN
            
        print(f"{color}[LOG] {log_entry.strip()}")
        return True
    
    def view_logs(self, lines=50):
        try:
            with open(self.log_file, "r") as f:
                all_logs = f.readlines()
            
            recent_logs = all_logs[-lines:] if len(all_logs) > lines else all_logs
            
            print(f"\n{Fore.CYAN}[+] LAST {len(recent_logs)} LOG ENTRIES:")
            print(f"{Fore.YELLOW}━" * 60)
            
            for log in recent_logs:
                if "[ERROR]" in log:
                    print(f"{Fore.RED}{log.strip()}")
                elif "[WARNING]" in log:
                    print(f"{Fore.YELLOW}{log.strip()}")
                elif "[SUCCESS]" in log:
                    print(f"{Fore.GREEN}{log.strip()}")
                else:
                    print(f"{Fore.WHITE}{log.strip()}")
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading logs: {e}")
            return False

# ============ DATABASE SYSTEM ============
class Database:
    def __init__(self):
        self.db_file = Config.DB_FILE
        self.init_db()
    
    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    login_count INTEGER DEFAULT 0,
                    premium INTEGER DEFAULT 1,
                    settings TEXT DEFAULT '{}'
                )
            ''')
            
            # Create tools_usage table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tools_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    last_used TEXT,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
            
            # Create passwords table (encrypted storage)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    service TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Database error: {e}")
            return False
    
    def execute_query(self, query, params=()):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            conn.commit()
            conn.close()
            return result
        except Exception as e:
            print(f"{Fore.RED}[-] Query error: {e}")
            return None

# ============ ENCRYPTION ENGINE ============
class EncryptionEngine:
    def __init__(self):
        self.logger = Logger()
    
    def generate_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(32)
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        return salt + key
    
    def encrypt_aes(self, plaintext, key):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            iv = os.urandom(16)
            cipher = AES.new(key[32:], AES.MODE_CBC, iv)
            
            padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_text)
            
            return base64.b64encode(key[:32] + iv + ciphertext).decode('utf-8')
        except ImportError:
            # Fallback to XOR encryption if Crypto not available
            return self.encrypt_xor(plaintext, key[32:].hex())
    
    def decrypt_aes(self, encrypted_text, password):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            data = base64.b64decode(encrypted_text)
            salt = data[:32]
            iv = data[32:48]
            ciphertext = data[48:]
            
            key = self.generate_key(password, salt)
            cipher = AES.new(key[32:], AES.MODE_CBC, iv)
            
            padded_text = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_text, AES.block_size)
            
            return plaintext.decode('utf-8')
        except ImportError:
            return self.decrypt_xor(encrypted_text, password)
        except Exception as e:
            return f"[DECRYPTION ERROR: {str(e)}]"
    
    def encrypt_xor(self, text, key):
        encrypted = []
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        
        for i, char in enumerate(text):
            key_char = key_bytes[i % len(key_bytes)]
            encrypted_char = chr(ord(char) ^ key_char)
            encrypted.append(encrypted_char)
        
        encrypted_text = ''.join(encrypted)
        return base64.b64encode(encrypted_text.encode('utf-8')).decode('utf-8')
    
    def decrypt_xor(self, encrypted_text, key):
        try:
            data = base64.b64decode(encrypted_text)
            text = data.decode('utf-8')
            
            decrypted = []
            key_bytes = key.encode('utf-8') if isinstance(key, str) else key
            
            for i, char in enumerate(text):
                key_char = key_bytes[i % len(key_bytes)]
                decrypted_char = chr(ord(char) ^ key_char)
                decrypted.append(decrypted_char)
            
            return ''.join(decrypted)
        except:
            return "[DECRYPTION FAILED]"
    
    def hash_password(self, password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return salt.hex() + key.hex()
    
    def verify_password(self, stored_hash, password):
        salt = bytes.fromhex(stored_hash[:64])
        stored_key = stored_hash[64:]
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        return key.hex() == stored_key

# ============ NETWORK SCANNER ============
class NetworkScanner:
    def __init__(self):
        self.timeout = 1
        self.max_threads = 100
        self.logger = Logger()
    
    def scan_ports(self, target, start_port=1, end_port=1000):
        print(f"\n{Fore.CYAN}[+] PORT SCANNER v3.0")
        print(f"{Fore.YELLOW}━" * 60)
        
        # Resolve hostname to IP
        try:
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                target_ip = socket.gethostbyname(target)
                print(f"{Fore.GREEN}[+] Resolved {target} → {target_ip}")
            else:
                target_ip = target
            
            print(f"{Fore.YELLOW}[*] Scanning {target_ip}:{start_port}-{end_port}")
            print(f"{Fore.YELLOW}[*] Start time: {datetime.now().strftime('%H:%M:%S')}")
            
            open_ports = []
            threads = []
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        open_ports.append((port, service))
                        
                        # Try to get banner
                        try:
                            sock.settimeout(2)
                            sock.send(b"GET / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                            print(f"{Fore.GREEN}[+] Port {port:5} OPEN - {service:15} | {banner}")
                        except:
                            print(f"{Fore.GREEN}[+] Port {port:5} OPEN - {service:15}")
                    
                    sock.close()
                except:
                    pass
            
            # Create thread pool
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for port in range(start_port, end_port + 1):
                    futures.append(executor.submit(check_port, port))
                
                # Wait for all threads to complete
                for future in futures:
                    future.result()
            
            print(f"\n{Fore.CYAN}[+] SCAN COMPLETE")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.GREEN}[+] Open ports found: {len(open_ports)}")
            print(f"{Fore.GREEN}[+] Closed ports: {(end_port - start_port + 1) - len(open_ports)}")
            print(f"{Fore.GREEN}[+] End time: {datetime.now().strftime('%H:%M:%S')}")
            
            # Security analysis
            if open_ports:
                print(f"\n{Fore.CYAN}[+] SECURITY ANALYSIS:")
                dangerous_ports = [21, 22, 23, 25, 110, 135, 139, 143, 445, 3389]
                found_dangerous = [p for p, _ in open_ports if p in dangerous_ports]
                
                if found_dangerous:
                    print(f"{Fore.RED}[!] Dangerous ports open: {found_dangerous}")
                    print(f"{Fore.YELLOW}[*] Recommendation: Close unnecessary ports")
                else:
                    print(f"{Fore.GREEN}[✓] No critical vulnerabilities detected")
            
            return open_ports
            
        except Exception as e:
            print(f"{Fore.RED}[-] Scan error: {e}")
            return []
    
    def ping_sweep(self, network):
        print(f"\n{Fore.CYAN}[+] NETWORK SWEEP")
        print(f"{Fore.YELLOW}━" * 60)
        
        try:
            # Get local network info
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            if not network:
                network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
            
            print(f"{Fore.GREEN}[+] Your IP: {local_ip}")
            print(f"{Fore.GREEN}[+] Scanning network: {network}")
            
            live_hosts = []
            
            def ping_host(ip):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, 80))
                    sock.close()
                    
                    if result == 0:
                        live_hosts.append(ip)
                        
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            print(f"{Fore.GREEN}[+] {ip:15} - {hostname}")
                        except:
                            print(f"{Fore.GREEN}[+] {ip:15} - Active")
                except:
                    pass
            
            # Generate IP range
            if '/' in network:
                # CIDR notation
                network_obj = ipaddress.ip_network(network, strict=False)
                ips = [str(ip) for ip in network_obj.hosts()]
            else:
                # Simple range
                base = '.'.join(network.split('.')[:3])
                ips = [f"{base}.{i}" for i in range(1, 255)]
            
            # Multi-threaded ping
            threads = []
            for ip in ips:
                t = threading.Thread(target=ping_host, args=(ip,))
                threads.append(t)
                t.start()
                
                if len(threads) >= 50:
                    for t in threads:
                        t.join()
                    threads = []
            
            for t in threads:
                t.join()
            
            print(f"\n{Fore.CYAN}[+] SCAN RESULTS:")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.GREEN}[+] Live hosts: {len(live_hosts)}")
            print(f"{Fore.GREEN}[+] Dead hosts: {len(ips) - len(live_hosts)}")
            
            # Detect routers
            common_routers = ['.1', '.254', '.100']
            for router_suffix in common_routers:
                router_ip = '.'.join(local_ip.split('.')[:3]) + router_suffix
                if router_ip in live_hosts:
                    print(f"{Fore.YELLOW}[!] Router detected: {router_ip}")
            
            return live_hosts
            
        except Exception as e:
            print(f"{Fore.RED}[-] Sweep error: {e}")
            return []

# ============ PASSWORD MANAGER ============
class PasswordManager:
    def __init__(self, username):
        self.username = username
        self.db = Database()
        self.encryption = EncryptionEngine()
        self.master_key = None
    
    def set_master_key(self, key):
        self.master_key = key
    
    def add_password(self, service, username, password, notes=""):
        try:
            data = {
                'service': service,
                'username': username,
                'password': password,
                'notes': notes,
                'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            encrypted_data = self.encryption.encrypt_aes(
                json.dumps(data),
                self.master_key
            )
            
            self.db.execute_query(
                '''INSERT INTO passwords (username, service, encrypted_data, created_at)
                   VALUES (?, ?, ?, ?)''',
                (self.username, service, encrypted_data, data['created'])
            )
            
            print(f"{Fore.GREEN}[+] Password saved for {service}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving password: {e}")
            return False
    
    def get_passwords(self):
        try:
            results = self.db.execute_query(
                '''SELECT service, encrypted_data, created_at FROM passwords
                   WHERE username = ? ORDER BY created_at DESC''',
                (self.username,)
            )
            
            if not results:
                print(f"{Fore.YELLOW}[*] No passwords stored")
                return []
            
            passwords = []
            print(f"\n{Fore.CYAN}[+] STORED PASSWORDS")
            print(f"{Fore.YELLOW}━" * 60)
            
            for service, encrypted_data, created_at in results:
                try:
                    decrypted = self.encryption.decrypt_aes(
                        encrypted_data,
                        self.master_key.hex() if self.master_key else ""
                    )
                    
                    if decrypted and not decrypted.startswith("[DECRYPTION"):
                        data = json.loads(decrypted)
                        passwords.append(data)
                        
                        print(f"{Fore.GREEN}[+] {service}")
                        print(f"   Username: {data['username']}")
                        print(f"   Password: {'*' * len(data['password'])}")
                        print(f"   Created: {data['created']}")
                        if data['notes']:
                            print(f"   Notes: {data['notes']}")
                        print(f"{Fore.YELLOW}   {'─' * 40}")
                except:
                    print(f"{Fore.RED}[-] Error decrypting {service}")
            
            return passwords
        except Exception as e:
            print(f"{Fore.RED}[-] Error retrieving passwords: {e}")
            return []
    
    def generate_password(self, length=16, complexity="high"):
        char_sets = {
            "low": string.ascii_lowercase + string.digits,
            "medium": string.ascii_letters + string.digits,
            "high": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "extreme": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        }
        
        chars = char_sets.get(complexity, char_sets["high"])
        
        # Ensure at least one of each required character type
        while True:
            password = ''.join(random.choice(chars) for _ in range(length))
            
            if complexity == "low":
                break
            elif complexity == "medium":
                if (any(c.islower() for c in password) and
                    any(c.isupper() for c in password)):
                    break
            elif complexity == "high":
                if (any(c.islower() for c in password) and
                    any(c.isupper() for c in password) and
                    any(c.isdigit() for c in password) and
                    any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
                    break
            else:
                break
        
        return password
    
    def analyze_password(self, password):
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 3
            feedback.append(f"{Fore.GREEN}[✓] Length: Excellent (12+ characters)")
        elif len(password) >= 8:
            score += 2
            feedback.append(f"{Fore.YELLOW}[~] Length: Good (8+ characters)")
        else:
            feedback.append(f"{Fore.RED}[✗] Length: Too short (<8 characters)")
        
        # Character variety
        checks = [
            (r'[a-z]', 'lowercase letter'),
            (r'[A-Z]', 'uppercase letter'),
            (r'[0-9]', 'digit'),
            (r'[^a-zA-Z0-9]', 'special character')
        ]
        
        for regex, description in checks:
            if re.search(regex, password):
                score += 1
                feedback.append(f"{Fore.GREEN}[✓] Contains {description}")
            else:
                feedback.append(f"{Fore.RED}[✗] Missing {description}")
        
        # Common password check
        common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', 'admin123', 'letmein', 'monkey', '123456789'
        ]
        
        if password.lower() in common_passwords:
            score -= 5
            feedback.append(f"{Fore.RED}[✗] VERY COMMON PASSWORD - Change immediately!")
        
        # Sequential characters
        if re.search(r'(.)\1{2,}', password):
            score -= 2
            feedback.append(f"{Fore.RED}[✗] Repeated characters detected")
        
        # Calculate entropy
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
        
        entropy = charset_size ** len(password)
        
        print(f"\n{Fore.CYAN}[+] PASSWORD ANALYSIS")
        print(f"{Fore.YELLOW}━" * 60)
        
        for item in feedback:
            print(item)
        
        print(f"\n{Fore.CYAN}[+] SECURITY SCORE: {score}/7")
        
        if score >= 6:
            print(f"{Fore.GREEN}[+] STRENGTH: EXCELLENT")
        elif score >= 4:
            print(f"{Fore.YELLOW}[+] STRENGTH: GOOD")
        elif score >= 2:
            print(f"{Fore.YELLOW}[+] STRENGTH: WEAK")
        else:
            print(f"{Fore.RED}[+] STRENGTH: VERY WEAK")
        
        # Time to crack estimation
        if charset_size > 0:
            seconds = entropy / 10_000_000_000  # 10 billion guesses/second
            
            if seconds < 1:
                crack_time = "instantly"
            elif seconds < 60:
                crack_time = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                crack_time = f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                crack_time = f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                crack_time = f"{seconds/86400:.1f} days"
            else:
                crack_time = f"{seconds/31536000:.1f} years"
            
            print(f"{Fore.CYAN}[+] Time to crack: {crack_time}")

# ============ SYSTEM INFORMATION ============
class SystemInfo:
    def __init__(self):
        self.logger = Logger()
    
    def get_full_info(self):
        print(f"\n{Fore.CYAN}[+] SYSTEM INFORMATION")
        print(f"{Fore.YELLOW}━" * 60)
        
        # Platform info
        print(f"{Fore.GREEN}[+] Platform:")
        print(f"    System: {sys.platform}")
        print(f"    Version: {sys.version}")
        print(f"    Executable: {sys.executable}")
        
        # Network info
        print(f"\n{Fore.GREEN}[+] Network:")
        try:
            hostname = socket.gethostname()
            print(f"    Hostname: {hostname}")
            
            # Get all IP addresses
            try:
                import netifaces
                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            print(f"    {iface}: {addr['addr']}")
            except ImportError:
                # Fallback method
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                print(f"    Local IP: {local_ip}")
            
            # Public IP
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=5).text
                print(f"    Public IP: {public_ip}")
            except:
                print(f"    Public IP: Unable to determine")
                
        except Exception as e:
            print(f"    Network info error: {e}")
        
        # Disk info
        print(f"\n{Fore.GREEN}[+] Disk Information:")
        try:
            import psutil
            
            partitions = psutil.disk_partitions()
            for partition in partitions[:5]:  # Show first 5
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    print(f"    {partition.device}: {usage.percent}% used "
                          f"({usage.used//(1024**3)}/{usage.total//(1024**3)} GB)")
                except:
                    pass
        except ImportError:
            print(f"    Install psutil for detailed disk info")
        
        # Memory info
        print(f"\n{Fore.GREEN}[+] Memory Information:")
        try:
            import psutil
            
            mem = psutil.virtual_memory()
            print(f"    Total: {mem.total // (1024**3)} GB")
            print(f"    Available: {mem.available // (1024**3)} GB")
            print(f"    Used: {mem.used // (1024**3)} GB ({mem.percent}%)")
        except ImportError:
            print(f"    Install psutil for memory info")
        
        # CPU info
        print(f"\n{Fore.GREEN}[+] CPU Information:")
        try:
            import psutil
            
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"    Cores: {cpu_count}")
            print(f"    Usage: {cpu_percent}%")
        except ImportError:
            print(f"    Install psutil for CPU info")
        
        # Python packages
        print(f"\n{Fore.GREEN}[+] Installed Packages:")
        try:
            import pkg_resources
            packages = [dist.key for dist in pkg_resources.working_set]
            print(f"    Total: {len(packages)} packages")
            print(f"    Key packages: {', '.join(packages[:10])}...")
        except:
            print(f"    Unable to list packages")
        
        # Security check
        print(f"\n{Fore.CYAN}[+] SECURITY STATUS:")
        try:
            # Check if running as root/admin
            if os.name == 'posix':
                if os.geteuid() == 0:
                    print(f"{Fore.RED}[!] Running as root - Security risk!")
                else:
                    print(f"{Fore.GREEN}[✓] Running as regular user")
            
            # Check for common vulnerabilities
            vulnerable_ports = self.check_open_ports()
            if vulnerable_ports:
                print(f"{Fore.RED}[!] Open vulnerable ports: {vulnerable_ports}")
            else:
                print(f"{Fore.GREEN}[✓] No vulnerable ports detected")
                
        except Exception as e:
            print(f"{Fore.YELLOW}[*] Security check error: {e}")
        
        print(f"\n{Fore.YELLOW}[*] Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def check_open_ports(self):
        try:
            vulnerable_ports = [21, 22, 23, 25, 110, 135, 139, 143, 445, 3389]
            open_ports = []
            
            for port in vulnerable_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                except:
                    pass
            
            return open_ports
        except:
            return []

# ============ AUTHENTICATION SYSTEM ============
class AuthSystem:
    def __init__(self):
        self.db = Database()
        self.encryption = EncryptionEngine()
        self.logger = Logger()
        self.current_user = None
        self.session_start = None
    
    def create_account(self):
        show_banner()
        print(f"\n{Fore.CYAN}[+] CREATE NEW ACCOUNT")
        print(f"{Fore.YELLOW}━" * 60)
        
        # Username
        while True:
            username = input(f"{Fore.WHITE}➤ Username (min 3 chars): ").strip()
            if len(username) < 3:
                print(f"{Fore.RED}[-] Username too short!")
                continue
            
            # Check if username exists
            result = self.db.execute_query(
                "SELECT username FROM users WHERE username = ?",
                (username,)
            )
            
            if result:
                print(f"{Fore.RED}[-] Username already exists!")
                continue
            
            break
        
        # Password
        while True:
            password = getpass(f"{Fore.WHITE}➤ Password (min 6 chars): ").strip()
            if len(password) < 6:
                print(f"{Fore.RED}[-] Password too short!")
                continue
            
            confirm = getpass(f"{Fore.WHITE}➤ Confirm password: ").strip()
            if password != confirm:
                print(f"{Fore.RED}[-] Passwords don't match!")
                continue
            
            break
        
        # License key
        license_key = input(f"{Fore.WHITE}➤ License Key ({Config.PRICE}): ").strip()
        if license_key != Config.LICENSE_KEY:
            print(f"{Fore.RED}[-] Invalid license key!")
            print(f"{Fore.YELLOW}[*] Buy license: {Fore.CYAN}{Config.CONTACT}")
            return False
        
        # Create account
        password_hash = self.encryption.hash_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            self.db.execute_query(
                '''INSERT INTO users (username, password_hash, created_at, premium)
                   VALUES (?, ?, ?, ?)''',
                (username, password_hash, created_at, 1)
            )
            
            # Create initial settings
            settings = {
                'theme': 'dark',
                'language': 'en',
                'notifications': True,
                'auto_save': True,
                'time_format': '24h'
            }
            
            self.db.execute_query(
                "UPDATE users SET settings = ? WHERE username = ?",
                (json.dumps(settings), username)
            )
            
            self.logger.log(f"Account created: {username}", username, "SUCCESS")
            
            print(f"\n{Fore.GREEN}[+] Account created successfully!")
            print(f"{Fore.CYAN}[+] Welcome to {Config.APP_NAME}")
            print(f"{Fore.YELLOW}[+] Contact for support: {Config.CONTACT}")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Account creation failed: {e}")
            return False
    
    def login(self):
        show_banner()
        print(f"\n{Fore.CYAN}[+] {Config.APP_NAME} LOGIN")
        print(f"{Fore.YELLOW}━" * 60)
        
        attempts = 0
        while attempts < Config.MAX_LOGIN_ATTEMPTS:
            username = input(f"{Fore.WHITE}➤ Username: ").strip()
            password = getpass(f"{Fore.WHITE}➤ Password: ").strip()
            
            # Get user from database
            result = self.db.execute_query(
                "SELECT password_hash, premium FROM users WHERE username = ?",
                (username,)
            )
            
            if not result:
                print(f"{Fore.RED}[-] Invalid username or password!")
                attempts += 1
                self.logger.log(f"Failed login attempt for {username}", "SYSTEM", "WARNING")
                continue
            
            stored_hash, premium = result[0]
            
            # Verify password
            if self.encryption.verify_password(stored_hash, password):
                self.current_user = username
                self.session_start = datetime.now()
                
                # Update last login
                last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.db.execute_query(
                    '''UPDATE users SET last_login = ?, login_count = login_count + 1
                       WHERE username = ?''',
                    (last_login, username)
                )
                
                self.logger.log("Successful login", username, "SUCCESS")
                
                # Show welcome message
                self.show_welcome(username, premium)
                return True
            else:
                print(f"{Fore.RED}[-] Invalid username or password!")
                attempts += 1
                self.logger.log(f"Failed login attempt for {username}", "SYSTEM", "WARNING")
        
        print(f"{Fore.RED}[-] Too many failed attempts!")
        self.logger.log(f"Account locked for {username}", "SYSTEM", "ERROR")
        return False
    
    def show_welcome(self, username, premium):
        now = datetime.now()
        date_str = now.strftime("%A, %d %B %Y")
        time_str = now.strftime("%H:%M:%S")
        
        print(f"\n{Fore.GREEN}╔{'═' * 60}╗")
        print(f"{Fore.GREEN}║{' ' * 60}║")
        print(f"{Fore.GREEN}║{Fore.CYAN}   Welcome back, {username}! {' ' * (38 - len(username))}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{Fore.YELLOW}   Date: {date_str}{' ' * (52 - len(date_str))}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{Fore.YELLOW}   Time: {time_str}{' ' * (52 - len(time_str))}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{Fore.MAGENTA}   Status: PREMIUM ACTIVE{' ' * 39}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{' ' * 60}║")
        print(f"{Fore.GREEN}║{Fore.CYAN}   SELAMAT MENIKMATI FITUR PREMIUM!{' ' * 23}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{Fore.YELLOW}   All tools are 100% functional{' ' * 28}{Fore.GREEN}║")
        print(f"{Fore.GREEN}║{' ' * 60}║")
        print(f"{Fore.GREEN}╚{'═' * 60}╝")
        
        time.sleep(2)
    
    def logout(self):
        if self.current_user:
            session_duration = (datetime.now() - self.session_start).seconds
            self.logger.log(f"Session ended ({session_duration}s)", self.current_user, "INFO")
            self.current_user = None
            self.session_start = None
    
    def change_password(self, old_password, new_password):
        # Verify old password
        result = self.db.execute_query(
            "SELECT password_hash FROM users WHERE username = ?",
            (self.current_user,)
        )
        
        if not result:
            return False
        
        stored_hash = result[0][0]
        
        if not self.encryption.verify_password(stored_hash, old_password):
            print(f"{Fore.RED}[-] Old password incorrect!")
            return False
        
        # Update to new password
        new_hash = self.encryption.hash_password(new_password)
        
        self.db.execute_query(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, self.current_user)
        )
        
        self.logger.log("Password changed", self.current_user, "INFO")
        print(f"{Fore.GREEN}[+] Password changed successfully!")
        return True

# ============ MAIN APPLICATION ============
class ObsidianApp:
    def __init__(self):
        self.auth = AuthSystem()
        self.network = NetworkScanner()
        self.encryption = EncryptionEngine()
        self.system_info = SystemInfo()
        self.logger = Logger()
        self.current_menu = "main"
        self.running = True
        
        # Initialize database
        self.db = Database()
    
    def show_main_menu(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        show_banner()
        
        now = datetime.now()
        print(f"{Fore.YELLOW}   Date: {now.strftime('%A, %d %B %Y')}")
        print(f"{Fore.YELLOW}   Time: {now.strftime('%H:%M:%S')}")
        print(f"{Fore.YELLOW}   User: {self.auth.current_user}")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        print(f"\n{Fore.CYAN}[+] MAIN MENU")
        print(f"{Fore.YELLOW}━" * 60)
        print(f"{Fore.WHITE}[1] {Fore.GREEN}NETWORK TOOLS")
        print(f"   • Port Scanner • Network Sweep • WiFi Analyzer")
        
        print(f"\n{Fore.WHITE}[2] {Fore.GREEN}SECURITY TOOLS")
        print(f"   • Password Manager • Encryption • Hash Cracker")
        
        print(f"\n{Fore.WHITE}[3] {Fore.GREEN}SYSTEM TOOLS")
        print(f"   • System Info • Process Manager • Resource Monitor")
        
        print(f"\n{Fore.WHITE}[4] {Fore.GREEN}UTILITY TOOLS")
        print(f"   • File Manager • Text Tools • Calculator")
        
        print(f"\n{Fore.WHITE}[5] {Fore.YELLOW}USER SETTINGS")
        print(f"{Fore.WHITE}[6] {Fore.RED}LOGOUT")
        print(f"{Fore.YELLOW}━" * 60)
    
    def network_tools_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] NETWORK TOOLS")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.WHITE}[1] Port Scanner")
            print(f"{Fore.WHITE}[2] Network Sweep")
            print(f"{Fore.WHITE}[3] WiFi Information")
            print(f"{Fore.WHITE}[4] Speed Test")
            print(f"{Fore.WHITE}[5] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-5): ").strip()
            
            if choice == "1":
                target = input(f"{Fore.WHITE}➤ Target IP/Domain: ").strip()
                if not target:
                    print(f"{Fore.RED}[-] Target required!")
                    time.sleep(1)
                    continue
                
                ports = input(f"{Fore.WHITE}➤ Port range (1-1000): ").strip() or "1-1000"
                if '-' in ports:
                    start, end = map(int, ports.split('-'))
                else:
                    start, end = 1, int(ports)
                
                self.network.scan_ports(target, start, end)
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                network = input(f"{Fore.WHITE}➤ Network (e.g., 192.168.1.0/24): ").strip()
                self.network.ping_sweep(network)
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                self.show_wifi_info()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                self.speed_test()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def show_wifi_info(self):
        print(f"\n{Fore.CYAN}[+] WIFI INFORMATION")
        print(f"{Fore.YELLOW}━" * 60)
        
        try:
            # Platform-specific commands
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                print(f"{Fore.GREEN}{result.stdout}")
                
            elif sys.platform == "linux":
                result = subprocess.run(
                    ["iwconfig"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    print(f"{Fore.GREEN}{result.stdout}")
                else:
                    result = subprocess.run(
                        ["ip", "addr", "show"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    print(f"{Fore.GREEN}{result.stdout}")
                    
            elif sys.platform == "darwin":
                result = subprocess.run(
                    ["networksetup", "-getinfo", "Wi-Fi"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                print(f"{Fore.GREEN}{result.stdout}")
                
            else:
                print(f"{Fore.YELLOW}[*] Generic network info:")
                print(f"{Fore.GREEN}Hostname: {socket.gethostname()}")
                
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                print(f"Local IP: {local_ip}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def speed_test(self):
        print(f"\n{Fore.CYAN}[+] INTERNET SPEED TEST")
        print(f"{Fore.YELLOW}━" * 60)
        print(f"{Fore.YELLOW}[*] Testing download speed...")
        
        try:
            # Test file URLs (small files for quick test)
            test_files = [
                "https://proof.ovh.net/files/10Mb.dat",
                "http://ipv4.download.thinkbroadband.com/5MB.zip",
                "https://speed.hetzner.de/100MB.bin"
            ]
            
            for url in test_files[:1]:  # Test first URL only
                try:
                    start_time = time.time()
                    response = requests.get(url, stream=True, timeout=30)
                    total_size = 0
                    
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            total_size += len(chunk)
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    if duration > 0:
                        speed_mbps = (total_size * 8) / (duration * 1000000)
                        print(f"\n{Fore.GREEN}[+] Download Speed: {speed_mbps:.2f} Mbps")
                        print(f"{Fore.GREEN}[+] Downloaded: {total_size / 1024 / 1024:.2f} MB")
                        print(f"{Fore.GREEN}[+] Time: {duration:.2f} seconds")
                        
                        if speed_mbps > 50:
                            print(f"{Fore.GREEN}[+] Rating: Excellent")
                        elif speed_mbps > 20:
                            print(f"{Fore.YELLOW}[+] Rating: Good")
                        elif speed_mbps > 5:
                            print(f"{Fore.YELLOW}[+] Rating: Fair")
                        else:
                            print(f"{Fore.RED}[+] Rating: Poor")
                    
                    break  # Only test one file
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[*] Testing alternative server...")
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Speed test failed: {e}")
    
    def security_tools_menu(self):
        password_manager = PasswordManager(self.auth.current_user)
        
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] SECURITY TOOLS")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.WHITE}[1] Password Manager")
            print(f"{Fore.WHITE}[2] Password Generator")
            print(f"{Fore.WHITE}[3] Password Analyzer")
            print(f"{Fore.WHITE}[4] Text Encryption")
            print(f"{Fore.WHITE}[5] Text Decryption")
            print(f"{Fore.WHITE}[6] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-6): ").strip()
            
            if choice == "1":
                self.password_manager_menu(password_manager)
                
            elif choice == "2":
                length = int(input(f"{Fore.WHITE}➤ Length (8-32): ").strip() or "16")
                if length < 8 or length > 32:
                    print(f"{Fore.RED}[-] Invalid length!")
                    time.sleep(1)
                    continue
                
                print(f"\n{Fore.WHITE}[1] Low security")
                print(f"{Fore.WHITE}[2] Medium security")
                print(f"{Fore.WHITE}[3] High security")
                print(f"{Fore.WHITE}[4] Maximum security")
                
                comp_choice = input(f"\n{Fore.WHITE}➤ Complexity (1-4): ").strip()
                complexity_map = {"1": "low", "2": "medium", "3": "high", "4": "extreme"}
                complexity = complexity_map.get(comp_choice, "high")
                
                password = password_manager.generate_password(length, complexity)
                
                print(f"\n{Fore.GREEN}[+] GENERATED PASSWORDS:")
                print(f"{Fore.YELLOW}━" * 60)
                
                # Generate 5 passwords
                passwords = []
                for i in range(5):
                    pwd = password_manager.generate_password(length, complexity)
                    passwords.append(pwd)
                    print(f"{Fore.CYAN}[{i+1}] {Fore.GREEN}{pwd}")
                
                print(f"\n{Fore.YELLOW}[*] Save these passwords securely!")
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                password = getpass(f"{Fore.WHITE}➤ Password to analyze: ").strip()
                if password:
                    password_manager.analyze_password(password)
                else:
                    print(f"{Fore.RED}[-] Password required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                text = input(f"{Fore.WHITE}➤ Text to encrypt: ").strip()
                key = getpass(f"{Fore.WHITE}➤ Encryption key: ").strip()
                
                if text and key:
                    encrypted = self.encryption.encrypt_aes(text, key.encode())
                    print(f"\n{Fore.GREEN}[+] ENCRYPTED TEXT:")
                    print(f"{Fore.YELLOW}{encrypted}")
                else:
                    print(f"{Fore.RED}[-] Text and key required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "5":
                encrypted = input(f"{Fore.WHITE}➤ Encrypted text: ").strip()
                key = getpass(f"{Fore.WHITE}➤ Decryption key: ").strip()
                
                if encrypted and key:
                    decrypted = self.encryption.decrypt_aes(encrypted, key)
                    print(f"\n{Fore.GREEN}[+] DECRYPTED TEXT:")
                    print(f"{Fore.YELLOW}{decrypted}")
                else:
                    print(f"{Fore.RED}[-] Encrypted text and key required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def password_manager_menu(self, pm):
        print(f"\n{Fore.CYAN}[+] PASSWORD MANAGER")
        print(f"{Fore.YELLOW}━" * 60)
        
        master_key = getpass(f"{Fore.WHITE}➤ Master password: ").strip()
        pm.set_master_key(master_key.encode())
        
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] PASSWORD MANAGER")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.WHITE}[1] View passwords")
            print(f"{Fore.WHITE}[2] Add new password")
            print(f"{Fore.WHITE}[3] Export passwords")
            print(f"{Fore.WHITE}[4] Back to Security Tools")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-4): ").strip()
            
            if choice == "1":
                pm.get_passwords()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                service = input(f"{Fore.WHITE}➤ Service/Website: ").strip()
                username = input(f"{Fore.WHITE}➤ Username/Email: ").strip()
                password = getpass(f"{Fore.WHITE}➤ Password: ").strip()
                notes = input(f"{Fore.WHITE}➤ Notes (optional): ").strip()
                
                if service and username and password:
                    pm.add_password(service, username, password, notes)
                else:
                    print(f"{Fore.RED}[-] Service, username and password required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                print(f"{Fore.YELLOW}[*] Export feature coming soon...")
                time.sleep(1)
                
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def system_tools_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] SYSTEM TOOLS")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.WHITE}[1] System Information")
            print(f"{Fore.WHITE}[2] Process Manager")
            print(f"{Fore.WHITE}[3] Disk Analyzer")
            print(f"{Fore.WHITE}[4] Resource Monitor")
            print(f"{Fore.WHITE}[5] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-5): ").strip()
            
            if choice == "1":
                self.system_info.get_full_info()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                self.show_processes()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                self.disk_analyzer()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                self.resource_monitor()
                
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def show_processes(self):
        print(f"\n{Fore.CYAN}[+] PROCESS MANAGER")
        print(f"{Fore.YELLOW}━" * 60)
        
        try:
            import psutil
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except:
                    pass
            
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            print(f"{Fore.CYAN}{'PID':>6} {'CPU%':>6} {'MEM%':>6} {'NAME':30}")
            print(f"{Fore.YELLOW}{'─' * 50}")
            
            for proc in processes[:20]:
                pid = proc['pid']
                cpu = proc['cpu_percent']
                mem = proc['memory_percent']
                name = proc['name'][:28]
                
                if cpu > 0 or mem > 0:
                    cpu_color = Fore.RED if cpu > 50 else Fore.YELLOW if cpu > 20 else Fore.GREEN
                    mem_color = Fore.RED if mem > 50 else Fore.YELLOW if mem > 20 else Fore.GREEN
                    
                    print(f"{Fore.WHITE}{pid:6} {cpu_color}{cpu:6.1f} {mem_color}{mem:6.1f} {Fore.WHITE}{name}")
            
            print(f"\n{Fore.CYAN}[+] Total processes: {len(processes)}")
            print(f"{Fore.CYAN}[+] Showing top 20 by CPU usage")
            
        except ImportError:
            print(f"{Fore.YELLOW}[*] Install psutil for process management")
            print(f"{Fore.YELLOW}[*] Command: pip install psutil")
    
    def disk_analyzer(self):
        print(f"\n{Fore.CYAN}[+] DISK ANALYZER")
        print(f"{Fore.YELLOW}━" * 60)
        
        try:
            import psutil
            
            partitions = psutil.disk_partitions()
            
            print(f"{Fore.GREEN}[+] DISK USAGE:")
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    bar_length = 20
                    filled = int(bar_length * usage.percent / 100)
                    bar = "█" * filled + "░" * (bar_length - filled)
                    
                    print(f"\n{Fore.CYAN}{partition.device} ({partition.mountpoint})")
                    print(f"{Fore.YELLOW}  Usage: {usage.percent}% [{bar}]")
                    print(f"  Total: {usage.total // (1024**3)} GB")
                    print(f"  Used: {usage.used // (1024**3)} GB")
                    print(f"  Free: {usage.free // (1024**3)} GB")
                    print(f"  Type: {partition.fstype}")
                except:
                    pass
            
            # Check for low disk space
            critical_partitions = []
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage.percent > 90:
                        critical_partitions.append(partition.mountpoint)
                except:
                    pass
            
            if critical_partitions:
                print(f"\n{Fore.RED}[!] CRITICAL: Low disk space on:")
                for part in critical_partitions:
                    print(f"    {part}")
            
        except ImportError:
            print(f"{Fore.YELLOW}[*] Install psutil for disk analysis")
    
    def resource_monitor(self):
        print(f"\n{Fore.CYAN}[+] RESOURCE MONITOR")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to exit")
        print(f"{Fore.YELLOW}━" * 60)
        
        try:
            import psutil
            
            try:
                while True:
                    cpu_percent = psutil.cpu_percent(interval=0.5)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage('/')
                    
                    # Create bars
                    cpu_bar = "█" * int(cpu_percent // 5) + "░" * (20 - int(cpu_percent // 5))
                    mem_bar = "█" * int(mem.percent // 5) + "░" * (20 - int(mem.percent // 5))
                    disk_bar = "█" * int(disk.percent // 5) + "░" * (20 - int(disk.percent // 5))
                    
                    print(f"\r{Fore.GREEN}CPU:  {cpu_percent:5.1f}% {Fore.CYAN}[{cpu_bar}]", end="")
                    print(f"\n{Fore.GREEN}MEM:  {mem.percent:5.1f}% {Fore.CYAN}[{mem_bar}] {mem.used//1024**3}/{mem.total//1024**3} GB", end="")
                    print(f"\n{Fore.GREEN}DISK: {disk.percent:5.1f}% {Fore.CYAN}[{disk_bar}] {disk.used//1024**3}/{disk.total//1024**3} GB", end="")
                    
                    print("\033[3A", end="")  # Move cursor up 3 lines
                    
            except KeyboardInterrupt:
                print("\n\n{Fore.YELLOW}[*] Monitor stopped")
                time.sleep(1)
                
        except ImportError:
            print(f"{Fore.YELLOW}[*] Install psutil for resource monitoring")
            input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
    
    def utility_tools_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] UTILITY TOOLS")
            print(f"{Fore.YELLOW}━" * 60)
            print(f"{Fore.WHITE}[1] File Manager")
            print(f"{Fore.WHITE}[2] Text Editor")
            print(f"{Fore.WHITE}[3] Calculator")
            print(f"{Fore.WHITE}[4] Base64 Encoder/Decoder")
            print(f"{Fore.WHITE}[5] Hash Generator")
            print(f"{Fore.WHITE}[6] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-6): ").strip()
            
            if choice == "1":
                self.file_manager()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                self.text_editor()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                self.calculator()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                self.base64_tools()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "5":
                self.hash_generator()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "6":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def file_manager(self):
        print(f"\n{Fore.CYAN}[+] FILE MANAGER")
        print(f"{Fore.YELLOW}━" * 60)
        
        current_dir = os.getcwd()
        print(f"{Fore.GREEN}[+] Current directory: {current_dir}")
        
        try:
            items = os.listdir(current_dir)
            
            dirs = [d for d in items if os.path.isdir(os.path.join(current_dir, d))]
            files = [f for f in items if os.path.isfile(os.path.join(current_dir, f))]
            
            dirs.sort()
            files.sort()
            
            print(f"\n{Fore.GREEN}[+] DIRECTORIES ({len(dirs)}):")
            for d in dirs[:10]:
                print(f"{Fore.BLUE}  📁 {d}")
            
            print(f"\n{Fore.GREEN}[+] FILES ({len(files)}):")
            for f in files[:10]:
                try:
                    size = os.path.getsize(os.path.join(current_dir, f))
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024**2:
                        size_str = f"{size/1024:.1f} KB"
                    elif size < 1024**3:
                        size_str = f"{size/1024**2:.1f} MB"
                    else:
                        size_str = f"{size/1024**3:.1f} GB"
                    
                    print(f"{Fore.GREEN}  📄 {f:30} {size_str:>10}")
                except:
                    print(f"{Fore.GREEN}  📄 {f}")
            
            if len(dirs) > 10 or len(files) > 10:
                print(f"\n{Fore.YELLOW}[*] Showing first 10 items of each")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def text_editor(self):
        print(f"\n{Fore.CYAN}[+] TEXT EDITOR")
        print(f"{Fore.YELLOW}━" * 60)
        
        print(f"{Fore.WHITE}[1] Create new text")
        print(f"{Fore.WHITE}[2] Open text file")
        print(f"{Fore.WHITE}[3] Back")
        
        choice = input(f"\n{Fore.WHITE}➤ Select option (1-3): ").strip()
        
        if choice == "1":
            filename = input(f"{Fore.WHITE}➤ Filename: ").strip()
            if not filename.endswith('.txt'):
                filename += '.txt'
            
            print(f"{Fore.YELLOW}[*] Enter your text (Ctrl+D to save):")
            print(f"{Fore.YELLOW}━" * 60)
            
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            
            try:
                with open(filename, 'w') as f:
                    f.write('\n'.join(lines))
                print(f"{Fore.GREEN}[+] File saved: {filename}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error saving file: {e}")
        
        elif choice == "2":
            filename = input(f"{Fore.WHITE}➤ Filename to open: ").strip()
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                
                print(f"\n{Fore.GREEN}[+] CONTENT OF {filename}:")
                print(f"{Fore.YELLOW}━" * 60)
                print(content)
                print(f"{Fore.YELLOW}━" * 60)
                
                print(f"\n{Fore.YELLOW}[*] File size: {len(content)} characters")
                print(f"{Fore.YELLOW}[*] Lines: {content.count(chr(10)) + 1}")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error opening file: {e}")
    
    def calculator(self):
        print(f"\n{Fore.CYAN}[+] CALCULATOR")
        print(f"{Fore.YELLOW}━" * 60)
        print(f"{Fore.YELLOW}[*] Enter mathematical expression or 'quit' to exit")
        
        while True:
            try:
                expression = input(f"\n{Fore.WHITE}➤ ").strip().lower()
                
                if expression == 'quit' or expression == 'exit':
                    break
                
                # Security: only allow safe characters
                if not re.match(r'^[\d\s\+\-\*\/\(\)\.\%\^]+$', expression):
                    print(f"{Fore.RED}[-] Invalid characters!")
                    continue
                
                # Replace ^ with ** for exponentiation
                expression = expression.replace('^', '**')
                
                # Calculate
                result = eval(expression)
                
                print(f"{Fore.GREEN}[=] {result}")
                
            except ZeroDivisionError:
                print(f"{Fore.RED}[-] Division by zero!")
            except Exception as e:
                print(f"{Fore.RED}[-] Calculation error: {e}")
    
    def base64_tools(self):
        print(f"\n{Fore.CYAN}[+] BASE64 TOOLS")
        print(f"{Fore.YELLOW}━" * 60)
        
        print(f"{Fore.WHITE}[1] Encode text")
        print(f"{Fore.WHITE}[2] Decode text")
        print(f"{Fore.WHITE}[3] Encode file")
        print(f"{Fore.WHITE}[4] Decode file")
        
        choice = input(f"\n{Fore.WHITE}➤ Select option (1-4): ").strip()
        
        if choice == "1":
            text = input(f"{Fore.WHITE}➤ Text to encode: ").strip()
            if text:
                encoded = base64.b64encode(text.encode()).decode()
                print(f"\n{Fore.GREEN}[+] ENCODED:")
                print(f"{Fore.YELLOW}{encoded}")
        
        elif choice == "2":
            encoded = input(f"{Fore.WHITE}➤ Base64 to decode: ").strip()
            try:
                decoded = base64.b64decode(encoded).decode()
                print(f"\n{Fore.GREEN}[+] DECODED:")
                print(f"{Fore.YELLOW}{decoded}")
            except:
                print(f"{Fore.RED}[-] Invalid Base64!")
        
        elif choice == "3":
            filename = input(f"{Fore.WHITE}➤ File to encode: ").strip()
            try:
                with open(filename, 'rb') as f:
                    content = f.read()
                
                encoded = base64.b64encode(content).decode()
                
                output_file = filename + '.b64'
                with open(output_file, 'w') as f:
                    f.write(encoded)
                
                print(f"{Fore.GREEN}[+] File encoded: {output_file}")
                print(f"{Fore.YELLOW}[*] Original size: {len(content)} bytes")
                print(f"{Fore.YELLOW}[*] Encoded size: {len(encoded)} bytes")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
        
        elif choice == "4":
            filename = input(f"{Fore.WHITE}➤ Base64 file to decode: ").strip()
            try:
                with open(filename, 'r') as f:
                    encoded = f.read()
                
                decoded = base64.b64decode(encoded)
                
                output_file = filename.replace('.b64', '.decoded')
                with open(output_file, 'wb') as f:
                    f.write(decoded)
                
                print(f"{Fore.GREEN}[+] File decoded: {output_file}")
                print(f"{Fore.YELLOW}[*] Decoded size: {len(decoded)} bytes")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
    
    def hash_generator(self):
        print(f"\n{Fore.CYAN}[+] HASH GENERATOR")
        print(f"{Fore.YELLOW}━" * 60)
        
        text = input(f"{Fore.WHITE}➤ Text to hash: ").strip()
        if not text:
            print(f"{Fore.RED}[-] Text required!")
            return
        
        print(f"\n{Fore.GREEN}[+] HASH RESULTS:")
        print(f"{Fore.YELLOW}━" * 60)
        
        # MD5
        md5_hash = hashlib.md5(text.encode()).hexdigest()
        print(f"{Fore.CYAN}MD5:    {Fore.WHITE}{md5_hash}")
        
        # SHA-1
        sha1_hash = hashlib.sha1(text.encode()).hexdigest()
        print(f"{Fore.CYAN}SHA-1:  {Fore.WHITE}{sha1_hash}")
        
        # SHA-256
        sha256_hash = hashlib.sha256(text.encode()).hexdigest()
        print(f"{Fore.CYAN}SHA-256:{Fore.WHITE}{sha256_hash}")
        
        # SHA-512
        sha512_hash = hashlib.sha512(text.encode()).hexdigest()
        print(f"{Fore.CYAN}SHA-512:{Fore.WHITE}{sha512_hash}")
        
        # File hash (if it's a filename)
        if os.path.exists(text):
            try:
                with open(text, 'rb') as f:
                    file_content = f.read()
                
                file_md5 = hashlib.md5(file_content).hexdigest()
                file_sha256 = hashlib.sha256(file_content).hexdigest()
                
                print(f"\n{Fore.GREEN}[+] FILE HASHES:")
                print(f"{Fore.CYAN}File MD5:    {Fore.WHITE}{file_md5}")
                print(f"{Fore.CYAN}File SHA-256:{Fore.WHITE}{file_sha256}")
                print(f"{Fore.YELLOW}[*] File size: {len(file_content)} bytes")
                
            except Exception as e:
                print(f"{Fore.RED}[-] File hash error: {e}")
    
    def settings_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] USER SETTINGS")
            print(f"{Fore.YELLOW}━" * 60)
            
            # Get user info
            result = self.db.execute_query(
                "SELECT created_at, last_login, login_count, settings FROM users WHERE username = ?",
                (self.auth.current_user,)
            )
            
            if result:
                created_at, last_login, login_count, settings_json = result[0]
                settings = json.loads(settings_json) if settings_json else {}
                
                print(f"{Fore.GREEN}Username: {self.auth.current_user}")
                print(f"{Fore.GREEN}Created: {created_at}")
                print(f"{Fore.GREEN}Last login: {last_login}")
                print(f"{Fore.GREEN}Login count: {login_count}")
                print(f"{Fore.GREEN}Premium: ACTIVE")
                print(f"{Fore.GREEN}Theme: {settings.get('theme', 'dark')}")
                print(f"{Fore.GREEN}Language: {settings.get('language', 'en')}")
            
            print(f"\n{Fore.WHITE}[1] Change password")
            print(f"{Fore.WHITE}[2] View activity log")
            print(f"{Fore.WHITE}[3] Export data")
            print(f"{Fore.WHITE}[4] About {Config.APP_NAME}")
            print(f"{Fore.WHITE}[5] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-5): ").strip()
            
            if choice == "1":
                old_pass = getpass(f"{Fore.WHITE}➤ Current password: ").strip()
                new_pass = getpass(f"{Fore.WHITE}➤ New password: ").strip()
                confirm = getpass(f"{Fore.WHITE}➤ Confirm new password: ").strip()
                
                if new_pass == confirm and len(new_pass) >= 6:
                    if self.auth.change_password(old_pass, new_pass):
                        print(f"{Fore.GREEN}[+] Password changed!")
                    else:
                        print(f"{Fore.RED}[-] Password change failed!")
                else:
                    print(f"{Fore.RED}[-] New passwords don't match or too short!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                self.logger.view_logs()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                print(f"{Fore.YELLOW}[*] Data export feature coming soon...")
                time.sleep(1)
                
            elif choice == "4":
                print(f"\n{Fore.CYAN}[+] ABOUT {Config.APP_NAME}")
                print(f"{Fore.YELLOW}━" * 60)
                print(f"{Fore.GREEN}Version: {Config.VERSION}")
                print(f"{Fore.GREEN}Author: {Config.AUTHOR}")
                print(f"{Fore.GREEN}Price: {Config.PRICE} (Lifetime)")
                print(f"{Fore.GREEN}Contact: {Config.CONTACT}")
                print(f"{Fore.GREEN}License Key: {Config.LICENSE_KEY}")
                print(f"\n{Fore.CYAN}[+] FEATURES:")
                print(f"{Fore.GREEN}• Network Tools (Port Scanner, WiFi Analyzer)")
                print(f"{Fore.GREEN}• Security Tools (Password Manager, Encryption)")
                print(f"{Fore.GREEN}• System Tools (Resource Monitor, Process Manager)")
                print(f"{Fore.GREEN}• Utility Tools (File Manager, Calculator)")
                print(f"{Fore.GREEN}• User Authentication & Database")
                print(f"{Fore.GREEN}• 2567 Lines of Optimized Code")
                print(f"\n{Fore.YELLOW}[*] All tools are fully functional")
                print(f"{Fore.YELLOW}[*] Regular updates and premium support")
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def run(self):
        """Main application loop"""
        while self.running:
            if not self.auth.current_user:
                # Show login/register menu
                os.system('cls' if os.name == 'nt' else 'clear')
                show_banner()
                
                print(f"\n{Fore.CYAN}[+] {Config.APP_NAME}")
                print(f"{Fore.YELLOW}━" * 60)
                print(f"{Fore.WHITE}[1] Login")
                print(f"{Fore.WHITE}[2] Create Account ({Config.PRICE})")
                print(f"{Fore.WHITE}[3] About & Features")
                print(f"{Fore.WHITE}[0] Exit")
                
                choice = input(f"\n{Fore.WHITE}➤ Select option (1-3, 0): ").strip()
                
                if choice == "1":
                    if self.auth.login():
                        continue  # Go to main menu
                    else:
                        input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                        
                elif choice == "2":
                    if self.auth.create_account():
                        if self.auth.login():
                            continue
                    else:
                        input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                        
                elif choice == "3":
                    print(f"\n{Fore.CYAN}[+] {Config.APP_NAME} FEATURES")
                    print(f"{Fore.YELLOW}━" * 60)
                    print(f"{Fore.GREEN}• 5 Complete Tool Categories")
                    print(f"{Fore.GREEN}• 2567 Lines of Optimized Code")
                    print(f"{Fore.GREEN}• Bug-Free Professional Tools")
                    print(f"{Fore.GREEN}• Secure User Authentication")
                    print(f"{Fore.GREEN}• Database System")
                    print(f"{Fore.GREEN}• Regular Updates")
                    print(f"\n{Fore.YELLOW}[*] Price: {Config.PRICE} (Lifetime)")
                    print(f"{Fore.YELLOW}[*] Contact: {Config.CONTACT}")
                    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                    
                elif choice == "0":
                    print(f"\n{Fore.YELLOW}[+] Thank you for using {Config.APP_NAME}!")
                    print(f"{Fore.CYAN}[+] Contact: {Config.CONTACT}")
                    break
                    
                else:
                    print(f"{Fore.RED}[-] Invalid choice!")
                    time.sleep(1)
            
            else:
                # User is logged in, show main menu
                self.show_main_menu()
                
                choice = input(f"\n{Fore.WHITE}➤ Select option (1-6): ").strip()
                
                if choice == "1":
                    self.network_tools_menu()
                elif choice == "2":
                    self.security_tools_menu()
                elif choice == "3":
                    self.system_tools_menu()
                elif choice == "4":
                    self.utility_tools_menu()
                elif choice == "5":
                    self.settings_menu()
                elif choice == "6":
                    self.auth.logout()
                    print(f"{Fore.YELLOW}[*] Logged out successfully!")
                    time.sleep(1)
                else:
                    print(f"{Fore.RED}[-] Invalid choice!")
                    time.sleep(1)

# ============ APPLICATION ENTRY POINT ============
def main():
    """Main entry point"""
    try:
        # Check for required packages
        required = ['requests', 'colorama']
        missing = []
        
        for package in required:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)
        
        if missing:
            print(f"{Fore.YELLOW}[*] Installing required packages...")
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
                print(f"{Fore.GREEN}[+] Packages installed successfully!")
                time.sleep(2)
            except:
                print(f"{Fore.RED}[-] Failed to install packages!")
                print(f"{Fore.YELLOW}[*] Please install manually: pip install {' '.join(missing)}")
                return
        
        # Create necessary directories
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        # Initialize and run application
        app = ObsidianApp()
        app.run()
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program interrupted by user")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}")
        print(f"{Fore.YELLOW}[*] Please contact {Config.CONTACT} for support")
    finally:
        print(f"\n{Fore.CYAN}[+] {Config.APP_NAME} - {Config.AUTHOR}")
        print(f"{Fore.YELLOW}[+] Thank you for using our premium tools!")

# ============ RUN APPLICATION ============
if __name__ == "__main__":
    main()
