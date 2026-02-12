#!/usr/bin/env python3
"""
🐼 LAZY PANDA v1.0.0 - Advanced IP Analysis Tool
Author: Ian Carter Kulani
Description: Lazy Panda, a comprehensive cybersecurity tool with one command for complete IP analysis
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import sqlite3
import ipaddress
import re
import datetime
import shutil
import urllib.parse
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict

# Optional imports with fallbacks
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Warning: discord.py not available. Install with: pip install discord.py")

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Warning: telethon not available. Install with: pip install telethon")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Warning: whois not available. Install with: pip install python-whois")

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("⚠️ Warning: colorama not available. Install with: pip install colorama")

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".lazy_panda"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "ip_analysis.db")
LOG_FILE = os.path.join(CONFIG_DIR, "lazy_panda.log")
REPORT_DIR = "lazy_panda_reports"
SCAN_RESULTS_DIR = os.path.join(REPORT_DIR, "scans")
BLOCKED_IPS_DIR = os.path.join(REPORT_DIR, "blocked")
TEMP_DIR = "lazy_panda_temp"

# Create directories
directories = [CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, BLOCKED_IPS_DIR, TEMP_DIR]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - LAZY_PANDA - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("LazyPanda")

# Color setup
if COLORAMA_AVAILABLE:
    class Colors:
        RED = Fore.RED + Style.BRIGHT
        GREEN = Fore.GREEN + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        BLUE = Fore.BLUE + Style.BRIGHT
        CYAN = Fore.CYAN + Style.BRIGHT
        MAGENTA = Fore.MAGENTA + Style.BRIGHT
        WHITE = Fore.WHITE + Style.BRIGHT
        RESET = Style.RESET_ALL
else:
    class Colors:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""

# =====================
# DATA CLASSES
# =====================
@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    target_ip: str
    timestamp: str
    ping_result: Dict[str, Any]
    traceroute_result: Dict[str, Any]
    port_scan_result: Dict[str, Any]
    geolocation_result: Dict[str, Any]
    traffic_monitor_result: Dict[str, Any]
    security_status: Dict[str, Any]
    recommendations: List[str]
    success: bool = True
    error: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()

@dataclass
class Config:
    """Configuration settings"""
    discord_enabled: bool = False
    discord_token: str = ""
    discord_channel_id: str = ""
    discord_admin_role: str = "Admin"
    
    telegram_enabled: bool = False
    telegram_api_id: str = ""
    telegram_api_hash: str = ""
    telegram_phone: str = ""
    telegram_channel_id: str = ""
    
    auto_block_threshold: int = 5
    scan_timeout: int = 30
    max_traceroute_hops: int = 30
    monitoring_duration: int = 60

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager for IP analysis history"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS ip_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT NOT NULL,
                analysis_result TEXT NOT NULL,
                source TEXT DEFAULT 'local'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                blocked_by TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                analysis_result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS discord_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                user_name TEXT,
                target_ip TEXT,
                success BOOLEAN
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS telegram_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                user_name TEXT,
                target_ip TEXT,
                success BOOLEAN
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def save_analysis(self, target_ip: str, analysis_result: Dict, source: str = "local"):
        """Save IP analysis to database"""
        try:
            self.cursor.execute('''
                INSERT INTO ip_analysis (target_ip, analysis_result, source)
                VALUES (?, ?, ?)
            ''', (target_ip, json.dumps(analysis_result), source))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return False
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent IP analyses"""
        try:
            self.cursor.execute('''
                SELECT * FROM ip_analysis ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get analyses: {e}")
            return []
    
    def block_ip(self, ip: str, reason: str, blocked_by: str = "system", analysis: Dict = None) -> bool:
        """Block an IP address"""
        try:
            analysis_json = json.dumps(analysis) if analysis else None
            self.cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_by, analysis_result)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, blocked_by, analysis_json))
            self.conn.commit()
            logger.info(f"IP {ip} blocked by {blocked_by}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.cursor.execute('''
                UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Get blocked IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY timestamp DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            self.cursor.execute('''
                SELECT 1 FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check blocked IP {ip}: {e}")
            return False
    
    def log_discord_command(self, user_id: str, user_name: str, target_ip: str, success: bool = True):
        """Log Discord command usage"""
        try:
            self.cursor.execute('''
                INSERT INTO discord_commands (user_id, user_name, target_ip, success)
                VALUES (?, ?, ?, ?)
            ''', (user_id, user_name, target_ip, success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Discord command: {e}")
    
    def log_telegram_command(self, user_id: str, user_name: str, target_ip: str, success: bool = True):
        """Log Telegram command usage"""
        try:
            self.cursor.execute('''
                INSERT INTO telegram_commands (user_id, user_name, target_ip, success)
                VALUES (?, ?, ?, ?)
            ''', (user_id, user_name, target_ip, success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Telegram command: {e}")
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Manage configuration settings"""
    
    @staticmethod
    def load_config() -> Config:
        """Load configuration from file"""
        config = Config()
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    
                    # Discord config
                    config.discord_enabled = data.get('discord', {}).get('enabled', False)
                    config.discord_token = data.get('discord', {}).get('token', '')
                    config.discord_channel_id = data.get('discord', {}).get('channel_id', '')
                    config.discord_admin_role = data.get('discord', {}).get('admin_role', 'Admin')
                    
                    # Telegram config
                    config.telegram_enabled = data.get('telegram', {}).get('enabled', False)
                    config.telegram_api_id = data.get('telegram', {}).get('api_id', '')
                    config.telegram_api_hash = data.get('telegram', {}).get('api_hash', '')
                    config.telegram_phone = data.get('telegram', {}).get('phone', '')
                    config.telegram_channel_id = data.get('telegram', {}).get('channel_id', '')
                    
                    # Other settings
                    config.auto_block_threshold = data.get('auto_block_threshold', 5)
                    config.scan_timeout = data.get('scan_timeout', 30)
                    config.max_traceroute_hops = data.get('max_traceroute_hops', 30)
                    config.monitoring_duration = data.get('monitoring_duration', 60)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return config
    
    @staticmethod
    def save_config(config: Config) -> bool:
        """Save configuration to file"""
        try:
            data = {
                "discord": {
                    "enabled": config.discord_enabled,
                    "token": config.discord_token,
                    "channel_id": config.discord_channel_id,
                    "admin_role": config.discord_admin_role
                },
                "telegram": {
                    "enabled": config.telegram_enabled,
                    "api_id": config.telegram_api_id,
                    "api_hash": config.telegram_api_hash,
                    "phone": config.telegram_phone,
                    "channel_id": config.telegram_channel_id
                },
                "auto_block_threshold": config.auto_block_threshold,
                "scan_timeout": config.scan_timeout,
                "max_traceroute_hops": config.max_traceroute_hops,
                "monitoring_duration": config.monitoring_duration
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

# =====================
# IP ANALYSIS ENGINE
# =====================
class IPAnalysisEngine:
    """Complete IP analysis engine with single command"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db = DatabaseManager()
    
    def execute_command(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, str(e)
    
    def ping_target(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Ping target IP address"""
        result = {
            "success": False,
            "output": "",
            "avg_rtt": None,
            "packet_loss": 100,
            "min_rtt": None,
            "max_rtt": None
        }
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            success, output = self.execute_command(cmd, timeout=10)
            result["success"] = success
            result["output"] = output[:500]
            
            # Parse RTT from output
            if success:
                if platform.system().lower() == 'windows':
                    match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                    if match:
                        result["min_rtt"] = int(match.group(1))
                        result["max_rtt"] = int(match.group(2))
                        result["avg_rtt"] = int(match.group(3))
                else:
                    match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/', output)
                    if match:
                        result["min_rtt"] = float(match.group(1))
                        result["avg_rtt"] = float(match.group(2))
                        result["max_rtt"] = float(match.group(3))
                
                # Parse packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    result["packet_loss"] = int(loss_match.group(1))
                else:
                    result["packet_loss"] = 0
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def traceroute_target(self, target: str) -> Dict[str, Any]:
        """Traceroute to target IP"""
        result = {
            "success": False,
            "output": "",
            "hops": []
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                cmd = ['tracert', '-d', '-h', str(self.config.max_traceroute_hops), target]
            else:
                if shutil.which('traceroute'):
                    cmd = ['traceroute', '-n', '-m', str(self.config.max_traceroute_hops), target]
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', '-n', '-m', str(self.config.max_traceroute_hops), target]
                else:
                    result["output"] = "No traceroute tool found"
                    return result
            
            success, output = self.execute_command(cmd, timeout=60)
            result["success"] = success
            result["output"] = output[:1000]
            
            # Parse hops
            lines = output.split('\n')
            for line in lines:
                if '1 ' in line or ' 1)' in line:
                    hop_match = re.search(r'(\d+)\s+([0-9.]+|\*)', line)
                    if hop_match:
                        hop_num = hop_match.group(1)
                        hop_ip = hop_match.group(2)
                        result["hops"].append({
                            "hop": hop_num,
                            "ip": hop_ip if hop_ip != '*' else 'Timeout'
                        })
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def scan_ports(self, target: str) -> Dict[str, Any]:
        """Scan common ports on target IP"""
        result = {
            "success": False,
            "output": "",
            "open_ports": [],
            "scan_type": "common_ports"
        }
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        try:
            # Use nmap if available
            if shutil.which('nmap'):
                cmd = ['nmap', '-T4', '-F', '--max-rtt-timeout', '100ms', 
                       '--max-retries', '1', '-Pn', target]
                success, output = self.execute_command(cmd, timeout=self.config.scan_timeout)
                result["success"] = success
                result["output"] = output[:1000]
                
                # Parse open ports from nmap output
                for line in output.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0].split('/')
                            if len(port_proto) == 2:
                                port = port_proto[0]
                                service = parts[2] if len(parts) > 2 else 'unknown'
                                result["open_ports"].append({
                                    "port": port,
                                    "protocol": "tcp",
                                    "service": service,
                                    "state": "open"
                                })
            else:
                # Fallback: socket scan
                result["success"] = True
                result["output"] = "Using fallback socket scanner"
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock_result = sock.connect_ex((target, port))
                        if sock_result == 0:
                            try:
                                service = socket.getservbyport(port)
                            except:
                                service = "unknown"
                            
                            result["open_ports"].append({
                                "port": port,
                                "protocol": "tcp",
                                "service": service,
                                "state": "open"
                            })
                        sock.close()
                    except:
                        pass
                
                result["output"] = f"Found {len(result['open_ports'])} open ports"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def get_geolocation(self, target: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        result = {
            "success": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "org": "Unknown"
        }
        
        try:
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result["success"] = True
                    result["country"] = data.get('country', 'Unknown')
                    result["region"] = data.get('regionName', 'Unknown')
                    result["city"] = data.get('city', 'Unknown')
                    result["isp"] = data.get('isp', 'Unknown')
                    result["lat"] = data.get('lat', 'Unknown')
                    result["lon"] = data.get('lon', 'Unknown')
                    result["org"] = data.get('org', 'Unknown')
        except Exception as e:
            logger.error(f"Geolocation error: {e}")
        
        return result
    
    def monitor_traffic(self, target: str) -> Dict[str, Any]:
        """Monitor traffic to/from target IP"""
        result = {
            "success": False,
            "output": "",
            "connections": [],
            "connection_count": 0,
            "threat_level": "low"
        }
        
        try:
            duration = self.config.monitoring_duration
            start_time = time.time()
            connections_seen = {}
            
            result["output"] = f"Monitoring traffic for {duration}s...\n"
            
            # Monitor for specified duration
            while time.time() - start_time < duration:
                try:
                    if platform.system().lower() == 'linux':
                        # Use netstat on Linux
                        success, output = self.execute_command(['netstat', '-tun'], timeout=5)
                        if success:
                            for line in output.split('\n'):
                                if target in line:
                                    parts = line.split()
                                    if len(parts) >= 6:
                                        proto = parts[0]
                                        local = parts[3]
                                        remote = parts[4]
                                        state = parts[5] if len(parts) > 5 else 'ESTABLISHED'
                                        
                                        conn_key = f"{proto}|{local}|{remote}"
                                        if conn_key not in connections_seen:
                                            connections_seen[conn_key] = {
                                                "protocol": proto,
                                                "local_address": local,
                                                "remote_address": remote,
                                                "state": state,
                                                "timestamp": datetime.datetime.now().isoformat()
                                            }
                except:
                    pass
                
                time.sleep(1)
            
            result["connections"] = list(connections_seen.values())
            result["connection_count"] = len(connections_seen)
            result["success"] = True
            
            # Determine threat level based on connections
            if len(connections_seen) > 20:
                result["threat_level"] = "high"
            elif len(connections_seen) > 10:
                result["threat_level"] = "medium"
            else:
                result["threat_level"] = "low"
            
            result["output"] += f"Found {len(connections_seen)} connections during monitoring"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def analyze_security(self, target: str, port_scan: Dict, traffic_monitor: Dict) -> Dict[str, Any]:
        """Analyze security status of target IP"""
        result = {
            "is_blocked": self.db.is_ip_blocked(target),
            "risk_score": 0,
            "risk_level": "low",
            "threats_detected": []
        }
        
        # Calculate risk score
        risk_score = 0
        
        # Check open ports
        open_ports_count = len(port_scan.get("open_ports", []))
        if open_ports_count > 10:
            risk_score += 30
            result["threats_detected"].append("Multiple open ports detected")
        elif open_ports_count > 5:
            risk_score += 15
            result["threats_detected"].append("Several open ports detected")
        elif open_ports_count > 0:
            risk_score += 5
        
        # Check for sensitive ports
        sensitive_ports = [22, 23, 3389, 5900]
        for port_info in port_scan.get("open_ports", []):
            try:
                port = int(port_info.get("port", 0))
                if port in sensitive_ports:
                    risk_score += 10
                    result["threats_detected"].append(f"Sensitive port {port} open")
            except:
                pass
        
        # Check traffic
        traffic_connections = traffic_monitor.get("connection_count", 0)
        if traffic_connections > 20:
            risk_score += 25
            result["threats_detected"].append("High traffic volume detected")
        elif traffic_connections > 10:
            risk_score += 10
            result["threats_detected"].append("Moderate traffic volume detected")
        
        # Check if previously blocked
        if result["is_blocked"]:
            risk_score += 50
            result["threats_detected"].append("Previously blocked IP address")
        
        # Determine risk level
        result["risk_score"] = risk_score
        if risk_score >= 70:
            result["risk_level"] = "critical"
        elif risk_score >= 40:
            result["risk_level"] = "high"
        elif risk_score >= 20:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        return result
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        ping_result = analysis.get("ping_result", {})
        if not ping_result.get("success", False):
            recommendations.append("⚠️ Target is not responding to ping - may be down or blocking ICMP")
        elif ping_result.get("packet_loss", 100) > 20:
            recommendations.append(f"📉 High packet loss ({ping_result.get('packet_loss', 0)}%) - network instability detected")
        
        port_scan = analysis.get("port_scan_result", {})
        open_ports = port_scan.get("open_ports", [])
        if len(open_ports) > 10:
            recommendations.append("🔓 Multiple open ports detected - consider closing unnecessary ports")
        
        for port_info in open_ports:
            port = port_info.get("port", "")
            if port in [23, 3389]:
                recommendations.append(f"🔐 Port {port} (telnet/RDP) is open - consider using SSH/VPN instead")
            elif port in [21]:
                recommendations.append(f"🔐 Port {port} (FTP) is open - consider using SFTP/FTPS")
        
        traffic = analysis.get("traffic_monitor_result", {})
        if traffic.get("threat_level") == "high":
            recommendations.append("🚨 High traffic volume detected - possible scanning or attack")
        
        geolocation = analysis.get("geolocation_result", {})
        if geolocation.get("country") not in ["Unknown", "United States"]:
            recommendations.append(f"🌍 International traffic from {geolocation.get('country')} - verify if expected")
        
        if analysis.get("security_status", {}).get("risk_level") in ["critical", "high"]:
            recommendations.append("🛡️ Consider blocking this IP address due to high risk")
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
        
        return recommendations
    
    def analyze_ip(self, target: str) -> IPAnalysisResult:
        """Complete IP analysis - single command"""
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(target)
            except ValueError:
                # Try to resolve hostname
                try:
                    target = socket.gethostbyname(target)
                except:
                    return IPAnalysisResult(
                        target_ip=target,
                        timestamp=datetime.datetime.now().isoformat(),
                        ping_result={"success": False, "output": "Invalid IP or hostname"},
                        traceroute_result={"success": False, "output": "Invalid IP or hostname"},
                        port_scan_result={"success": False, "output": "Invalid IP or hostname"},
                        geolocation_result={"success": False},
                        traffic_monitor_result={"success": False, "output": "Invalid IP or hostname"},
                        security_status={},
                        recommendations=["Invalid IP address or hostname"],
                        success=False,
                        error="Invalid IP or hostname"
                    )
            
            logger.info(f"Starting analysis for IP: {target}")
            
            # Perform all checks
            ping_result = self.ping_target(target)
            traceroute_result = self.traceroute_target(target)
            port_scan_result = self.scan_ports(target)
            geolocation_result = self.get_geolocation(target)
            traffic_monitor_result = self.monitor_traffic(target)
            security_status = self.analyze_security(target, port_scan_result, traffic_monitor_result)
            
            # Generate recommendations
            analysis_dict = {
                "ping_result": ping_result,
                "port_scan_result": port_scan_result,
                "traffic_monitor_result": traffic_monitor_result,
                "geolocation_result": geolocation_result,
                "security_status": security_status
            }
            recommendations = self.generate_recommendations(analysis_dict)
            
            # Create result object
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result=ping_result,
                traceroute_result=traceroute_result,
                port_scan_result=port_scan_result,
                geolocation_result=geolocation_result,
                traffic_monitor_result=traffic_monitor_result,
                security_status=security_status,
                recommendations=recommendations,
                success=True
            )
            
            # Save to database
            self.db.save_analysis(target, asdict(result))
            
            logger.info(f"Analysis completed for IP: {target}")
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed for {target}: {e}")
            return IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result={"success": False, "output": str(e)},
                traceroute_result={"success": False, "output": str(e)},
                port_scan_result={"success": False, "output": str(e)},
                geolocation_result={"success": False},
                traffic_monitor_result={"success": False, "output": str(e)},
                security_status={},
                recommendations=["Analysis failed due to error"],
                success=False,
                error=str(e)
            )

# =====================
# DISCORD BOT
# =====================
class LazyPandaDiscord:
    """Discord bot for Lazy Panda"""
    
    def __init__(self, config: Config, engine: IPAnalysisEngine):
        self.config = config
        self.engine = engine
        self.bot = None
        self.running = False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("Discord.py not installed")
            return False
        
        if not self.config.discord_token:
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            
            self.bot = commands.Bot(
                command_prefix='!', 
                intents=intents,
                help_command=None
            )
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot connected as {self.bot.user}')
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="!enter_target <ip> | !help"
                    )
                )
            
            @self.bot.command(name='help')
            async def help_command(ctx):
                """Show help"""
                embed = discord.Embed(
                    title="🐼 Lazy Panda v1.0.0 - Help",
                    description="**Single Command IP Analysis Tool**",
                    color=discord.Color.blue()
                )
                
                embed.add_field(
                    name="📋 **COMMANDS**",
                    value="`!enter_target <ip>` - Complete IP analysis (ping, traceroute, port scan, geolocation, traffic)\n`!help` - Show this help\n`!status` - Bot status\n`!blocked` - List blocked IPs",
                    inline=False
                )
                
                embed.add_field(
                    name="📊 **ANALYSIS INCLUDES**",
                    value="• Ping response & latency\n• Network route (traceroute)\n• Open port scanning\n• IP geolocation\n• Traffic monitoring\n• Security risk assessment",
                    inline=False
                )
                
                embed.add_field(
                    name="💡 **EXAMPLE**",
                    value="`!enter_target 8.8.8.8`\n`!enter_target 192.168.1.1`\n`!enter_target example.com`",
                    inline=False
                )
                
                embed.set_footer(text=f"Requested by {ctx.author.display_name}")
                await ctx.send(embed=embed)
            
            @self.bot.command(name='enter_target')
            async def enter_target_command(ctx, target: str):
                """Complete IP analysis - single command"""
                await ctx.send(f"🐼 Lazy Panda is analyzing `{target}`...\nThis may take up to 2 minutes.")
                
                # Check admin role
                is_admin = False
                if ctx.guild:
                    user_roles = [role.name for role in ctx.author.roles]
                    if self.config.discord_admin_role in user_roles or ctx.author == ctx.guild.owner:
                        is_admin = True
                
                # Perform analysis
                result = self.engine.analyze_ip(target)
                
                # Log command
                self.engine.db.log_discord_command(str(ctx.author.id), ctx.author.name, target, result.success)
                
                if result.success:
                    # Create comprehensive embed
                    embed = discord.Embed(
                        title=f"🐼 Lazy Panda IP Analysis: {result.target_ip}",
                        color=discord.Color.red() if result.security_status.get('risk_level') in ['critical', 'high'] else discord.Color.green(),
                        timestamp=datetime.datetime.now()
                    )
                    
                    # Ping results
                    ping = result.ping_result
                    ping_text = f"{'✅ Online' if ping.get('success') else '❌ Offline'}"
                    if ping.get('avg_rtt'):
                        ping_text += f"\n⏱️ Avg: {ping.get('avg_rtt')}ms"
                        ping_text += f"\n📊 Loss: {ping.get('packet_loss', 0)}%"
                    embed.add_field(name="🏓 Ping", value=ping_text, inline=True)
                    
                    # Geolocation
                    geo = result.geolocation_result
                    geo_text = f"🌍 {geo.get('country', 'Unknown')}\n🏙️ {geo.get('city', 'Unknown')}\n🏢 {geo.get('isp', 'Unknown')[:20]}"
                    embed.add_field(name="📍 Location", value=geo_text, inline=True)
                    
                    # Ports
                    ports = result.port_scan_result.get('open_ports', [])
                    port_text = f"🔓 Open ports: {len(ports)}"
                    if ports:
                        top_ports = [str(p.get('port', '')) for p in ports[:5]]
                        port_text += f"\nPorts: {', '.join(top_ports)}"
                        if len(ports) > 5:
                            port_text += f" +{len(ports)-5} more"
                    embed.add_field(name="🔌 Port Scan", value=port_text, inline=True)
                    
                    # Traffic
                    traffic = result.traffic_monitor_result
                    traffic_emoji = '🔴' if traffic.get('threat_level') == 'high' else '🟡' if traffic.get('threat_level') == 'medium' else '🟢'
                    traffic_text = f"{traffic_emoji} Level: {traffic.get('threat_level', 'low').upper()}\n📊 Connections: {traffic.get('connection_count', 0)}"
                    embed.add_field(name="📡 Traffic", value=traffic_text, inline=True)
                    
                    # Security risk
                    security = result.security_status
                    risk_emoji = '🔴' if security.get('risk_level') == 'critical' else '🟠' if security.get('risk_level') == 'high' else '🟡' if security.get('risk_level') == 'medium' else '🟢'
                    risk_text = f"{risk_emoji} Risk: {security.get('risk_level', 'unknown').upper()}\n📈 Score: {security.get('risk_score', 0)}"
                    if security.get('is_blocked'):
                        risk_text += "\n🔒 BLOCKED"
                    embed.add_field(name="🛡️ Security", value=risk_text, inline=True)
                    
                    # Traceroute summary
                    trace = result.traceroute_result
                    trace_text = f"🛣️ Hops: {len(trace.get('hops', []))}\n{trace.get('output', '')[:100]}"
                    embed.add_field(name="🔍 Traceroute", value=trace_text[:100], inline=True)
                    
                    # Recommendations
                    if result.recommendations:
                        rec_text = "\n".join(result.recommendations[:3])
                        embed.add_field(name="💡 Recommendations", value=rec_text[:200], inline=False)
                    
                    embed.set_footer(text=f"Analysis completed in {result.timestamp}")
                    await ctx.send(embed=embed)
                    
                    # Send detailed report as file
                    report_file = f"{TEMP_DIR}/analysis_{ctx.message.id}.json"
                    with open(report_file, 'w') as f:
                        json.dump(asdict(result), f, indent=2)
                    await ctx.send(file=discord.File(report_file))
                    os.remove(report_file)
                    
                    # Auto-block suggestion for admins
                    if is_admin and security.get('risk_level') in ['critical', 'high']:
                        block_msg = await ctx.send(f"⚠️ High risk IP detected. Use `!block_ip {target}` to block?")
                        await block_msg.add_reaction('✅')
                        await block_msg.add_reaction('❌')
                else:
                    await ctx.send(f"❌ Analysis failed: {result.error}")
            
            @self.bot.command(name='block_ip')
            @commands.has_permissions(administrator=True)
            async def block_ip_command(ctx, ip: str, *, reason: str = "High risk detected by Lazy Panda"):
                """Block an IP address (Admin only)"""
                try:
                    ipaddress.ip_address(ip)
                except:
                    await ctx.send(f"❌ Invalid IP address: {ip}")
                    return
                
                # Store analysis if available
                analyses = self.engine.db.get_recent_analyses(1)
                analysis = None
                if analyses and analyses[0].get('target_ip') == ip:
                    analysis = json.loads(analyses[0].get('analysis_result', '{}'))
                
                success = self.engine.db.block_ip(ip, reason, f"discord:{ctx.author}", analysis)
                
                if success:
                    embed = discord.Embed(
                        title="🔒 IP Blocked",
                        description=f"**IP:** `{ip}`\n**Reason:** {reason}\n**Blocked by:** {ctx.author.mention}",
                        color=discord.Color.red(),
                        timestamp=datetime.datetime.now()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ Failed to block {ip}")
            
            @self.bot.command(name='unblock_ip')
            @commands.has_permissions(administrator=True)
            async def unblock_ip_command(ctx, ip: str):
                """Unblock an IP address (Admin only)"""
                success = self.engine.db.unblock_ip(ip)
                
                if success:
                    embed = discord.Embed(
                        title="🔓 IP Unblocked",
                        description=f"**IP:** `{ip}`\n**Unblocked by:** {ctx.author.mention}",
                        color=discord.Color.green(),
                        timestamp=datetime.datetime.now()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ Failed to unblock {ip}")
            
            @self.bot.command(name='blocked')
            async def blocked_ips_command(ctx):
                """List blocked IPs"""
                blocked = self.engine.db.get_blocked_ips(active_only=True)
                
                if not blocked:
                    embed = discord.Embed(
                        title="🔒 Blocked IPs",
                        description="No IPs are currently blocked.",
                        color=discord.Color.green()
                    )
                    await ctx.send(embed=embed)
                    return
                
                embed = discord.Embed(
                    title=f"🔒 Blocked IPs ({len(blocked)})",
                    color=discord.Color.red(),
                    timestamp=datetime.datetime.now()
                )
                
                for i, ip_data in enumerate(blocked[:10]):
                    embed.add_field(
                        name=f"{i+1}. `{ip_data['ip_address']}`",
                        value=f"Blocked: {ip_data['timestamp'][:10]}\nReason: {ip_data.get('reason', 'N/A')[:50]}",
                        inline=True
                    )
                
                if len(blocked) > 10:
                    embed.set_footer(text=f"And {len(blocked) - 10} more...")
                
                await ctx.send(embed=embed)
            
            @self.bot.command(name='status')
            async def status_command(ctx):
                """Bot status"""
                embed = discord.Embed(
                    title="🐼 Lazy Panda Status",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name="🤖 Bot", value="✅ Online", inline=True)
                embed.add_field(name="📊 Analyses", value=self.engine.db.get_recent_analyses(1)[0].get('target_ip', 'None') if self.engine.db.get_recent_analyses(1) else 'None', inline=True)
                embed.add_field(name="🔒 Blocked IPs", value=len(self.engine.db.get_blocked_ips(active_only=True)), inline=True)
                
                await ctx.send(embed=embed)
            
            self.running = True
            await self.bot.start(self.config.discord_token)
            return True
            
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            return False
    
    def start_bot_thread(self):
        """Start Discord bot in thread"""
        if self.config.discord_enabled and self.config.discord_token:
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot thread error: {e}")

# =====================
# TELEGRAM BOT
# =====================
class LazyPandaTelegram:
    """Telegram bot for Lazy Panda"""
    
    def __init__(self, config: Config, engine: IPAnalysisEngine):
        self.config = config
        self.engine = engine
        self.client = None
        self.running = False
    
    async def start(self):
        """Start Telegram bot"""
        if not TELETHON_AVAILABLE:
            logger.error("Telethon not installed")
            return False
        
        if not self.config.telegram_api_id or not self.config.telegram_api_hash:
            logger.error("Telegram API credentials not configured")
            return False
        
        try:
            self.client = TelegramClient(
                'lazy_panda_session',
                self.config.telegram_api_id,
                self.config.telegram_api_hash
            )
            
            @self.client.on(events.NewMessage(pattern=r'^/(start|help|enter_target|blocked|status)'))
            async def handler(event):
                await self.handle_command(event)
            
            await self.client.start(phone=self.config.telegram_phone)
            logger.info("Telegram bot started")
            
            self.running = True
            await self.client.run_until_disconnected()
            return True
            
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")
            return False
    
    async def handle_command(self, event):
        """Handle Telegram commands"""
        message = event.message.message
        sender = await event.get_sender()
        
        if not message.startswith('/'):
            return
        
        command_parts = message.split()
        command = command_parts[0][1:]
        args = command_parts[1:] if len(command_parts) > 1 else []
        
        logger.info(f"Telegram command from {sender.username}: {command}")
        
        if command in ['start', 'help']:
            await self.send_help(event)
        
        elif command == 'enter_target':
            if not args:
                await event.reply("❌ Please provide an IP address or hostname.\nUsage: `/enter_target <ip>`")
                return
            
            target = args[0]
            processing_msg = await event.reply(f"🐼 Lazy Panda is analyzing `{target}`...\nThis may take up to 2 minutes.")
            
            # Perform analysis
            result = self.engine.analyze_ip(target)
            
            # Log command
            self.engine.db.log_telegram_command(str(sender.id), sender.username or "unknown", target, result.success)
            
            if result.success:
                # Format response
                response = self.format_telegram_result(result)
                await processing_msg.delete()
                await event.reply(response, parse_mode='html')
            else:
                await processing_msg.delete()
                await event.reply(f"❌ Analysis failed: {result.error}")
        
        elif command == 'blocked':
            blocked = self.engine.db.get_blocked_ips(active_only=True)
            if not blocked:
                await event.reply("🔒 No IPs are currently blocked.")
            else:
                response = "🔒 <b>Blocked IPs:</b>\n\n"
                for ip_data in blocked[:10]:
                    response += f"• <code>{ip_data['ip_address']}</code>\n"
                    response += f"  Reason: {ip_data.get('reason', 'N/A')[:50]}\n"
                    response += f"  Date: {ip_data['timestamp'][:10]}\n\n"
                
                if len(blocked) > 10:
                    response += f"... and {len(blocked) - 10} more"
                
                await event.reply(response, parse_mode='html')
        
        elif command == 'status':
            analyses = self.engine.db.get_recent_analyses(1)
            blocked_count = len(self.engine.db.get_blocked_ips(active_only=True))
            
            response = "🐼 <b>Lazy Panda Status</b>\n\n"
            response += "✅ Bot: Online\n"
            if analyses:
                response += f"📊 Last analysis: {analyses[0].get('target_ip', 'N/A')}\n"
            response += f"🔒 Blocked IPs: {blocked_count}"
            
            await event.reply(response, parse_mode='html')
    
    def format_telegram_result(self, result: IPAnalysisResult) -> str:
        """Format analysis result for Telegram"""
        response = f"🐼 <b>Lazy Panda IP Analysis: {result.target_ip}</b>\n"
        response += f"🕐 {result.timestamp[:19]}\n"
        response += "═══════════════════════\n\n"
        
        # Ping
        ping = result.ping_result
        ping_icon = '✅' if ping.get('success') else '❌'
        response += f"{ping_icon} <b>PING:</b>\n"
        if ping.get('success'):
            if ping.get('avg_rtt'):
                response += f"  • Avg RTT: {ping.get('avg_rtt')}ms\n"
                response += f"  • Loss: {ping.get('packet_loss', 0)}%\n"
            else:
                response += f"  • Online\n"
        else:
            response += f"  • Offline/Unreachable\n"
        response += "\n"
        
        # Location
        geo = result.geolocation_result
        response += f"📍 <b>LOCATION:</b>\n"
        response += f"  • Country: {geo.get('country', 'Unknown')}\n"
        response += f"  • City: {geo.get('city', 'Unknown')}\n"
        response += f"  • ISP: {geo.get('isp', 'Unknown')[:30]}\n"
        response += "\n"
        
        # Ports
        ports = result.port_scan_result.get('open_ports', [])
        response += f"🔌 <b>OPEN PORTS:</b> {len(ports)}\n"
        if ports:
            port_list = [str(p.get('port', '')) for p in ports[:10]]
            response += f"  • {', '.join(port_list)}\n"
            if len(ports) > 10:
                response += f"  • ... and {len(ports)-10} more\n"
        response += "\n"
        
        # Traffic
        traffic = result.traffic_monitor_result
        traffic_level = traffic.get('threat_level', 'low').upper()
        traffic_icon = '🔴' if traffic.get('threat_level') == 'high' else '🟡' if traffic.get('threat_level') == 'medium' else '🟢'
        response += f"{traffic_icon} <b>TRAFFIC:</b>\n"
        response += f"  • Level: {traffic_level}\n"
        response += f"  • Connections: {traffic.get('connection_count', 0)}\n"
        response += "\n"
        
        # Security
        security = result.security_status
        risk_icon = '🔴' if security.get('risk_level') == 'critical' else '🟠' if security.get('risk_level') == 'high' else '🟡' if security.get('risk_level') == 'medium' else '🟢'
        response += f"{risk_icon} <b>SECURITY:</b>\n"
        response += f"  • Risk: {security.get('risk_level', 'unknown').upper()}\n"
        response += f"  • Score: {security.get('risk_score', 0)}\n"
        if security.get('is_blocked'):
            response += f"  • Status: 🔒 BLOCKED\n"
        response += "\n"
        
        # Traceroute summary
        trace = result.traceroute_result
        response += f"🔍 <b>TRACEROUTE:</b>\n"
        response += f"  • Hops: {len(trace.get('hops', []))}\n"
        if trace.get('hops'):
            first_hop = trace['hops'][0] if trace['hops'] else {}
            last_hop = trace['hops'][-1] if trace['hops'] else {}
            if first_hop and last_hop:
                response += f"  • First: {first_hop.get('ip', 'Unknown')}\n"
                response += f"  • Last: {last_hop.get('ip', 'Unknown')}\n"
        response += "\n"
        
        # Recommendations
        if result.recommendations:
            response += f"💡 <b>RECOMMENDATIONS:</b>\n"
            for rec in result.recommendations[:3]:
                response += f"  • {rec}\n"
            response += "\n"
        
        response += "═══════════════════════\n"
        response += f"🆔 Analysis ID: {result.timestamp}"
        
        return response
    
    async def send_help(self, event):
        """Send help message"""
        help_text = """
🐼 <b>Lazy Panda v1.0.0 - Telegram Commands</b>

<b>MAIN COMMAND:</b>
/enter_target &lt;ip&gt; - Complete IP analysis
   • Ping & latency
   • Traceroute
   • Port scanning
   • Geolocation
   • Traffic monitoring
   • Security assessment

<b>OTHER COMMANDS:</b>
/blocked - List blocked IPs
/status - Bot status
/help - Show this help
/start - Show this help

<b>EXAMPLES:</b>
/enter_target 8.8.8.8
/enter_target 192.168.1.1
/enter_target example.com

<b>Note:</b> Analysis takes 1-2 minutes
        """
        await event.reply(help_text, parse_mode='html')
    
    def start_bot_thread(self):
        """Start Telegram bot in thread"""
        if self.config.telegram_enabled and self.config.telegram_api_id:
            thread = threading.Thread(target=self._run_telegram_bot, daemon=True)
            thread.start()
            logger.info("Telegram bot started in background")
            return True
        return False
    
    def _run_telegram_bot(self):
        """Run Telegram bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Telegram bot thread error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class LazyPandaApp:
    """Main application"""
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.engine = IPAnalysisEngine(self.config)
        self.discord_bot = LazyPandaDiscord(self.config, self.engine)
        self.telegram_bot = LazyPandaTelegram(self.config, self.engine)
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}                                                                           {Colors.CYAN}║
║{Colors.WHITE}       🐼  ██╗      █████╗ ███████╗██╗   ██╗    ██████╗  █████╗ ███╗   ██╗██████╗  █████╗  {Colors.CYAN}║
║{Colors.WHITE}       🐼  ██║     ██╔══██╗╚══███╔╝╚██╗ ██╔╝    ██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗ {Colors.CYAN}║
║{Colors.WHITE}       🐼  ██║     ███████║  ███╔╝  ╚████╔╝     ██████╔╝███████║██╔██╗ ██║██║  ██║███████║ {Colors.CYAN}║
║{Colors.WHITE}       🐼  ██║     ██╔══██║ ███╔╝    ╚██╔╝      ██╔═══╝ ██╔══██║██║╚██╗██║██║  ██║██╔══██║ {Colors.CYAN}║
║{Colors.WHITE}       🐼  ███████╗██║  ██║███████╗   ██║       ██║     ██║  ██║██║ ╚████║██████╔╝██║  ██║ {Colors.CYAN}║
║{Colors.WHITE}       🐼  ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ {Colors.CYAN}║
║{Colors.WHITE}                                                                           {Colors.CYAN}║
║{Colors.WHITE}                         🚀 LAZY PANDA v1.0.0 🚀                           {Colors.CYAN}║
║{Colors.WHITE}                  Complete IP Analysis - One Command                       {Colors.CYAN}║
║{Colors.WHITE}                                                                           {Colors.CYAN}║
╠═══════════════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  📌 ONE COMMAND - COMPLETE ANALYSIS                                    {Colors.CYAN}║
║{Colors.GREEN}  🔍 Ping | Traceroute | Port Scan | Geolocation | Traffic | Security   {Colors.CYAN}║
║{Colors.GREEN}  🤖 Discord & Telegram Ready - Use !enter_target /enter_target         {Colors.CYAN}║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)
    
    def setup_configuration(self):
        """Setup configuration"""
        print(f"\n{Colors.CYAN}🐼 Lazy Panda Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Discord setup
        setup_discord = input(f"\n{Colors.YELLOW}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
        if setup_discord == 'y':
            self.config.discord_enabled = True
            self.config.discord_token = input(f"{Colors.YELLOW}Enter Discord bot token: {Colors.RESET}").strip()
            self.config.discord_channel_id = input(f"{Colors.YELLOW}Enter channel ID (optional): {Colors.RESET}").strip()
            self.config.discord_admin_role = input(f"{Colors.YELLOW}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        
        # Telegram setup
        setup_telegram = input(f"\n{Colors.YELLOW}Setup Telegram bot? (y/n): {Colors.RESET}").strip().lower()
        if setup_telegram == 'y':
            self.config.telegram_enabled = True
            self.config.telegram_api_id = input(f"{Colors.YELLOW}Enter Telegram API ID: {Colors.RESET}").strip()
            self.config.telegram_api_hash = input(f"{Colors.YELLOW}Enter Telegram API Hash: {Colors.RESET}").strip()
            self.config.telegram_phone = input(f"{Colors.YELLOW}Enter phone number (optional): {Colors.RESET}").strip()
            self.config.telegram_channel_id = input(f"{Colors.YELLOW}Enter channel ID (optional): {Colors.RESET}").strip()
        
        # Save configuration
        ConfigManager.save_config(self.config)
        print(f"{Colors.GREEN}✅ Configuration saved!{Colors.RESET}")
    
    def start_bots(self):
        """Start Discord and Telegram bots"""
        if self.config.discord_enabled:
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Discord bot started! Use !enter_target <ip>{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        
        if self.config.telegram_enabled:
            if self.telegram_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Telegram bot started! Use /enter_target <ip>{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.YELLOW}┌─────────────────{Colors.WHITE} LAZY PANDA COMMANDS {Colors.YELLOW}─────────────────┐{Colors.RESET}

{Colors.CYAN}🐼 MAIN COMMAND:{Colors.RESET}
  {Colors.GREEN}enter_target <ip/hostname>{Colors.RESET} - Complete IP analysis
    Performs: Ping, Traceroute, Port Scan, Geolocation, Traffic Monitor, Security Assessment

{Colors.CYAN}📋 OTHER COMMANDS:{Colors.RESET}
  {Colors.GREEN}help{Colors.RESET}            - Show this help
  {Colors.GREEN}blocked{Colors.RESET}         - List blocked IPs
  {Colors.GREEN}block <ip> [reason]{Colors.RESET} - Block an IP (Admin)
  {Colors.GREEN}unblock <ip>{Colors.RESET}     - Unblock an IP (Admin)
  {Colors.GREEN}history{Colors.RESET}         - Show recent analyses
  {Colors.GREEN}status{Colors.RESET}          - Show system status
  {Colors.GREEN}config{Colors.RESET}          - Configure Discord/Telegram
  {Colors.GREEN}clear{Colors.RESET}           - Clear screen
  {Colors.GREEN}exit{Colors.RESET}            - Exit application

{Colors.CYAN}🤖 DISCORD COMMANDS:{Colors.RESET}
  {Colors.GREEN}!enter_target <ip>{Colors.RESET} - Complete IP analysis
  {Colors.GREEN}!blocked{Colors.RESET}        - List blocked IPs
  {Colors.GREEN}!status{Colors.RESET}         - Bot status
  {Colors.GREEN}!help{Colors.RESET}           - Show Discord help

{Colors.CYAN}📱 TELEGRAM COMMANDS:{Colors.RESET}
  {Colors.GREEN}/enter_target <ip>{Colors.RESET} - Complete IP analysis
  {Colors.GREEN}/blocked{Colors.RESET}        - List blocked IPs
  {Colors.GREEN}/status{Colors.RESET}         - Bot status
  {Colors.GREEN}/help{Colors.RESET}           - Show Telegram help

{Colors.CYAN}💡 EXAMPLES:{Colors.RESET}
  {Colors.WHITE}enter_target 8.8.8.8{Colors.RESET}
  {Colors.WHITE}enter_target 192.168.1.1{Colors.RESET}
  {Colors.WHITE}enter_target example.com{Colors.RESET}
  {Colors.WHITE}block 192.168.1.100 Port scan detected{Colors.RESET}

{Colors.YELLOW}└─────────────────────────────────────────────────────┘{Colors.RESET}
        """
        print(help_text)
    
    def process_command(self, command: str):
        """Process local CLI command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'enter_target':
            if not args:
                print(f"{Colors.RED}❌ Please provide an IP address or hostname{Colors.RESET}")
                print(f"{Colors.YELLOW}Usage: enter_target <ip/hostname>{Colors.RESET}")
                return
            
            target = args[0]
            print(f"\n{Colors.CYAN}🐼 Lazy Panda is analyzing {Colors.WHITE}{target}{Colors.CYAN}...{Colors.RESET}")
            print(f"{Colors.YELLOW}This may take up to 2 minutes...{Colors.RESET}\n")
            
            # Perform analysis
            result = self.engine.analyze_ip(target)
            
            if result.success:
                self.print_analysis_result(result)
            else:
                print(f"{Colors.RED}❌ Analysis failed: {result.error}{Colors.RESET}")
        
        elif cmd == 'blocked':
            blocked = self.engine.db.get_blocked_ips(active_only=True)
            if not blocked:
                print(f"{Colors.GREEN}🔒 No IPs are currently blocked.{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}🔒 Blocked IPs ({len(blocked)}):{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                for ip_data in blocked:
                    print(f"\n{Colors.WHITE}IP: {ip_data['ip_address']}{Colors.RESET}")
                    print(f"  Blocked: {ip_data['timestamp'][:19]}")
                    print(f"  Reason: {ip_data.get('reason', 'N/A')}")
                    print(f"  Blocked by: {ip_data.get('blocked_by', 'system')}")
        
        elif cmd == 'block' and len(args) >= 1:
            ip = args[0]
            reason = ' '.join(args[1:]) if len(args) > 1 else "Manual block"
            
            try:
                ipaddress.ip_address(ip)
                success = self.engine.db.block_ip(ip, reason, "cli")
                if success:
                    print(f"{Colors.GREEN}✅ IP {ip} blocked successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to block IP {ip}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}❌ Invalid IP address: {ip}{Colors.RESET}")
        
        elif cmd == 'unblock' and len(args) >= 1:
            ip = args[0]
            success = self.engine.db.unblock_ip(ip)
            if success:
                print(f"{Colors.GREEN}✅ IP {ip} unblocked successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to unblock IP {ip}{Colors.RESET}")
        
        elif cmd == 'history':
            analyses = self.engine.db.get_recent_analyses(10)
            if analyses:
                print(f"\n{Colors.CYAN}📊 Recent Analyses:{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                for analysis in analyses:
                    print(f"\n{Colors.WHITE}Target: {analysis['target_ip']}{Colors.RESET}")
                    print(f"  Time: {analysis['timestamp'][:19]}")
                    print(f"  Source: {analysis['source']}")
            else:
                print(f"{Colors.YELLOW}📊 No analyses found{Colors.RESET}")
        
        elif cmd == 'status':
            analyses = self.engine.db.get_recent_analyses(1)
            blocked_count = len(self.engine.db.get_blocked_ips(active_only=True))
            
            print(f"\n{Colors.CYAN}🐼 Lazy Panda Status:{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"\n{Colors.GREEN}✅ System: Online{Colors.RESET}")
            print(f"📊 Database: {DATABASE_FILE}")
            if analyses:
                print(f"🔍 Last analysis: {analyses[0]['target_ip']} ({analyses[0]['timestamp'][:19]})")
            print(f"🔒 Blocked IPs: {blocked_count}")
            print(f"\n🤖 Discord: {'✅ Enabled' if self.config.discord_enabled else '❌ Disabled'}")
            print(f"📱 Telegram: {'✅ Enabled' if self.config.telegram_enabled else '❌ Disabled'}")
        
        elif cmd == 'config':
            self.setup_configuration()
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}👋 Thank you for using Lazy Panda!{Colors.RESET}")
        
        else:
            print(f"{Colors.RED}❌ Unknown command: {cmd}{Colors.RESET}")
            print(f"{Colors.YELLOW}Type 'help' for available commands{Colors.RESET}")
    
    def print_analysis_result(self, result: IPAnalysisResult):
        """Print analysis result in formatted way"""
        print(f"\n{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.WHITE}🐼 LAZY PANDA IP ANALYSIS: {Colors.CYAN}{result.target_ip}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.WHITE}📅 Time: {Colors.YELLOW}{result.timestamp[:19]}{Colors.RESET}")
        
        # Ping results
        ping = result.ping_result
        ping_icon = f"{Colors.GREEN}✅" if ping.get('success') else f"{Colors.RED}❌"
        print(f"\n{ping_icon}{Colors.WHITE} PING:{Colors.RESET}")
        if ping.get('success'):
            if ping.get('avg_rtt'):
                print(f"  • Avg RTT: {Colors.CYAN}{ping.get('avg_rtt')}ms{Colors.RESET}")
                print(f"  • Packet Loss: {Colors.YELLOW}{ping.get('packet_loss', 0)}%{Colors.RESET}")
            else:
                print(f"  • {Colors.GREEN}Online{Colors.RESET}")
        else:
            print(f"  • {Colors.RED}Offline/Unreachable{Colors.RESET}")
        
        # Geolocation
        geo = result.geolocation_result
        if geo.get('success'):
            print(f"\n{Colors.WHITE}📍 LOCATION:{Colors.RESET}")
            print(f"  • Country: {Colors.CYAN}{geo.get('country', 'Unknown')}{Colors.RESET}")
            print(f"  • Region: {Colors.CYAN}{geo.get('region', 'Unknown')}{Colors.RESET}")
            print(f"  • City: {Colors.CYAN}{geo.get('city', 'Unknown')}{Colors.RESET}")
            print(f"  • ISP: {Colors.CYAN}{geo.get('isp', 'Unknown')}{Colors.RESET}")
            print(f"  • Coordinates: {Colors.YELLOW}{geo.get('lat', 'Unknown')}, {geo.get('lon', 'Unknown')}{Colors.RESET}")
        
        # Port scan
        ports = result.port_scan_result.get('open_ports', [])
        print(f"\n{Colors.WHITE}🔌 OPEN PORTS: {Colors.CYAN}{len(ports)}{Colors.RESET}")
        if ports:
            for port_info in ports[:15]:
                port_color = Colors.RED if int(port_info.get('port', 0)) in [21,22,23,3389,5900] else Colors.YELLOW
                print(f"  • Port {port_color}{port_info.get('port', '')}{Colors.RESET} - {port_info.get('service', 'unknown')}")
            if len(ports) > 15:
                print(f"  • ... and {len(ports)-15} more")
        
        # Traffic monitoring
        traffic = result.traffic_monitor_result
        traffic_color = Colors.RED if traffic.get('threat_level') == 'high' else Colors.YELLOW if traffic.get('threat_level') == 'medium' else Colors.GREEN
        print(f"\n{Colors.WHITE}📡 TRAFFIC MONITORING:{Colors.RESET}")
        print(f"  • Threat Level: {traffic_color}{traffic.get('threat_level', 'low').upper()}{Colors.RESET}")
        print(f"  • Connections: {Colors.CYAN}{traffic.get('connection_count', 0)}{Colors.RESET}")
        
        # Security assessment
        security = result.security_status
        risk_color = Colors.RED if security.get('risk_level') in ['critical', 'high'] else Colors.YELLOW if security.get('risk_level') == 'medium' else Colors.GREEN
        print(f"\n{Colors.WHITE}🛡️ SECURITY ASSESSMENT:{Colors.RESET}")
        print(f"  • Risk Level: {risk_color}{security.get('risk_level', 'unknown').upper()}{Colors.RESET}")
        print(f"  • Risk Score: {Colors.CYAN}{security.get('risk_score', 0)}{Colors.RESET}")
        if security.get('is_blocked'):
            print(f"  • Status: {Colors.RED}🔒 BLOCKED{Colors.RESET}")
        
        if security.get('threats_detected'):
            print(f"\n{Colors.RED}⚠️ Threats Detected:{Colors.RESET}")
            for threat in security['threats_detected'][:5]:
                print(f"  • {Colors.YELLOW}{threat}{Colors.RESET}")
        
        # Traceroute summary
        trace = result.traceroute_result
        print(f"\n{Colors.WHITE}🔍 TRACEROUTE:{Colors.RESET}")
        if trace.get('success'):
            print(f"  • Hops: {Colors.CYAN}{len(trace.get('hops', []))}{Colors.RESET}")
            if trace.get('hops'):
                first_hop = trace['hops'][0] if trace['hops'] else {}
                last_hop = trace['hops'][-1] if trace['hops'] else {}
                if first_hop:
                    print(f"  • First hop: {Colors.CYAN}{first_hop.get('ip', 'Unknown')}{Colors.RESET}")
                if last_hop:
                    print(f"  • Last hop: {Colors.CYAN}{last_hop.get('ip', 'Unknown')}{Colors.RESET}")
        else:
            print(f"  • {Colors.RED}{trace.get('output', 'Failed')[:50]}{Colors.RESET}")
        
        # Recommendations
        if result.recommendations:
            print(f"\n{Colors.WHITE}💡 RECOMMENDATIONS:{Colors.RESET}")
            for rec in result.recommendations:
                rec_color = Colors.RED if 'block' in rec.lower() or 'risk' in rec.lower() else Colors.YELLOW
                print(f"  • {rec_color}{rec}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Analysis completed successfully{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Print banner
        self.print_banner()
        
        # Check if first run
        if not os.path.exists(CONFIG_FILE):
            print(f"{Colors.YELLOW}📝 First time setup...{Colors.RESET}")
            self.setup_configuration()
        
        # Start bots
        self.start_bots()
        
        # Print help
        self.print_help()
        
        # Main command loop
        while self.running:
            try:
                prompt = f"{Colors.CYAN}[{Colors.WHITE}lazy-panda{Colors.CYAN}]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.engine.db.close()
        
        print(f"\n{Colors.GREEN}✅ Lazy Panda shutdown complete.{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Logs saved to: {LOG_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}💾 Database: {DATABASE_FILE}{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.CYAN}🐼 Starting Lazy Panda v1.0.0...{Colors.RESET}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        # Create and run application
        app = LazyPandaApp()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()