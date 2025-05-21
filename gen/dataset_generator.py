import random
import pandas as pd
from datetime import datetime, timedelta, timezone
import numpy as np
from typing import List, Dict, Optional, Union
import logging
import os
from dataclasses import dataclass
from faker import Faker
import argparse
import json
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class AttackConfig:
    """Configuration for generating attack patterns."""
    attack_type: str
    frequency: float  # Attacks per hour
    duration_hours: float
    severity: str  # 'Low', 'Medium', 'High'
    source_ips: int  # Number of unique IPs to use
    target_paths: List[str]  # Target paths for the attack
    payloads: List[str]  # Attack payloads to use

class LogGenerator:
    """Generates synthetic log data with customizable attack patterns."""
    
    def __init__(self, output_dir: str = "logs"):
        """Initialize the log generator."""
        self.output_dir = output_dir
        self.fake = Faker()
        os.makedirs(output_dir, exist_ok=True)
        
        # Common HTTP methods and status codes
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        self.status_codes = {
            'success': [200, 201, 204],
            'redirect': [301, 302, 304],
            'client_error': [400, 401, 403, 404, 429],
            'server_error': [500, 502, 503, 504]
        }
        
        # Common user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)'
        ]
        
        # Common paths
        self.normal_paths = [
            '/', '/about', '/contact', '/products', '/services',
            '/blog', '/login', '/register', '/search', '/api/v1/users',
            '/api/v1/products', '/api/v1/orders', '/admin', '/dashboard'
        ]
        
        # Attack patterns
        self.attack_patterns = {
            'brute_force': {
                'paths': ['/login', '/admin/login', '/api/v1/auth'],
                'methods': ['POST'],
                'payloads': [
                    'username=admin&password=admin',
                    'username=root&password=root',
                    'username=admin&password=password123',
                    'username=administrator&password=admin123'
                ]
            },
            'sql_injection': {
                'paths': ['/search', '/api/v1/users', '/api/v1/products'],
                'methods': ['GET', 'POST'],
                'payloads': [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT * FROM users; --",
                    "' OR 1=1; --"
                ]
            },
            'xss': {
                'paths': ['/search', '/comment', '/api/v1/feedback'],
                'methods': ['POST', 'GET'],
                'payloads': [
                    "<script>alert('xss')</script>",
                    "<img src=x onerror=alert('xss')>",
                    "javascript:alert('xss')",
                    "<svg onload=alert('xss')>"
                ]
            },
            'path_traversal': {
                'paths': ['/download', '/api/v1/files', '/static'],
                'methods': ['GET'],
                'payloads': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config",
                    "../../../var/log/auth.log",
                    "....//....//....//etc/shadow"
                ]
            }
        }
    
    def generate_ip(self, is_attack: bool = False) -> str:
        """Generate a random IP address."""
        if is_attack:
            # Generate IPs from specific ranges for attacks
            ranges = [
                (f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}", 0.3),
                (f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}", 0.3),
                (f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}", 0.2),
                (self.fake.ipv4(), 0.2)
            ]
            return random.choices([r[0] for r in ranges], 
                                weights=[r[1] for r in ranges])[0]
        return self.fake.ipv4()
    
    def generate_timestamp(self, start_time: datetime, 
                          end_time: datetime) -> datetime:
        """Generate a random timestamp between start and end time."""
        time_diff = end_time - start_time
        random_seconds = random.randint(0, int(time_diff.total_seconds()))
        # Create timestamp with UTC timezone
        timestamp = start_time + timedelta(seconds=random_seconds)
        return timestamp.replace(tzinfo=timezone.utc)
    
    def generate_normal_request(self, timestamp: datetime) -> Dict:
        """Generate a normal (non-attack) log entry."""
        method = random.choice(self.methods)
        path = random.choice(self.normal_paths)
        status = random.choice(
            random.choice(list(self.status_codes.values()))
        )
        size = random.randint(100, 10000)
        
        return {
            'timestamp': timestamp,
            'ip': self.generate_ip(),
            'method': method,
            'path': path,
            'status': status,
            'size': size,
            'user_agent': random.choice(self.user_agents),
            'is_attack': False,
            'attack_type': None
        }
    
    def generate_attack_request(self, timestamp: datetime, 
                              attack_config: AttackConfig) -> Dict:
        """Generate an attack log entry."""
        pattern = self.attack_patterns[attack_config.attack_type]
        method = random.choice(pattern['methods'])
        path = random.choice(attack_config.target_paths)
        payload = random.choice(pattern['payloads'])
        
        # For brute force attacks, use appropriate status codes
        if attack_config.attack_type == 'brute_force':
            status = random.choices(
                [401, 403],  # Failed login attempts typically return 401 or 403
                weights=[0.7, 0.3]  # More likely to get 401 for invalid credentials
            )[0]
        else:
            # For other attacks, use a wider range of error codes
            status = random.choices(
                [403, 404, 429, 500],
                weights=[0.3, 0.3, 0.2, 0.2]
            )[0]
        
        size = random.randint(50, 500)  # Attack requests are usually smaller
        
        return {
            'timestamp': timestamp,
            'ip': self.generate_ip(is_attack=True),
            'method': method,
            'path': f"{path}?{payload}" if method == 'GET' else path,
            'status': status,
            'size': size,
            'user_agent': random.choice(self.user_agents),
            'is_attack': True,
            'attack_type': attack_config.attack_type
        }
    
    def generate_dataset(self, 
                        duration_hours: float,
                        normal_requests_per_hour: int,
                        attack_configs: List[AttackConfig],
                        output_file: str = "synthetic_logs.log") -> None:
        """Generate a synthetic dataset with normal and attack traffic."""
        logger.info("Generating synthetic dataset...")
        
        # Calculate time range with UTC timezone
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=duration_hours)
        
        # Generate timestamps for all requests
        total_normal_requests = int(normal_requests_per_hour * duration_hours)
        timestamps = [
            self.generate_timestamp(start_time, end_time)
            for _ in range(total_normal_requests)
        ]
        
        # Pre-generate attack IPs for each attack type
        attack_ips = {}
        for config in attack_configs:
            # Generate a fixed set of IPs for this attack type
            attack_ips[config.attack_type] = [
                self.generate_ip(is_attack=True) 
                for _ in range(config.source_ips)
            ]
            logger.info(f"Generated {len(attack_ips[config.attack_type])} IPs for {config.attack_type} attacks")
        
        # Add attack timestamps and generate attack entries
        log_entries = []
        for config in attack_configs:
            attack_requests = int(config.frequency * config.duration_hours)
            attack_start = start_time + timedelta(
                hours=random.uniform(0, duration_hours - config.duration_hours)
            )
            attack_end = attack_start + timedelta(hours=config.duration_hours)
            
            # Generate attack timestamps
            attack_timestamps = [
                self.generate_timestamp(attack_start, attack_end)
                for _ in range(attack_requests)
            ]
            
            # Generate attack entries using the pre-generated IPs
            for timestamp in attack_timestamps:
                attack_ip = random.choice(attack_ips[config.attack_type])
                entry = self.generate_attack_request(timestamp, config)
                entry['ip'] = attack_ip  # Override the IP with our pre-generated one
                log_entries.append(entry)
        
        # Add normal requests
        for timestamp in timestamps:
            log_entries.append(self.generate_normal_request(timestamp))
        
        # Sort all entries by timestamp
        log_entries.sort(key=lambda x: x['timestamp'])
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(log_entries)
        
        # Write logs in Common Log Format
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            for entry in log_entries:
                # Format timestamp in CLF format with timezone
                clf_timestamp = entry['timestamp'].strftime('%d/%b/%Y:%H:%M:%S %z')
                
                # Format the log line in CLF format
                log_line = (
                    f'{entry["ip"]} - - [{clf_timestamp}] '
                    f'"{entry["method"]} {entry["path"]} HTTP/1.1" '
                    f'{entry["status"]} {entry["size"]} '
                    f'"-" "{entry["user_agent"]}"\n'
                )
                f.write(log_line)
        
        # Generate summary
        total_requests = len(df)
        attack_requests = df['is_attack'].sum()
        attack_types = df[df['is_attack']]['attack_type'].value_counts()
        
        # Log attack IP distribution
        for attack_type in attack_configs:
            attack_df = df[df['attack_type'] == attack_type.attack_type]
            ip_counts = attack_df['ip'].value_counts()
            logger.info(f"\n{attack_type.attack_type} attack IP distribution (top 5):")
            logger.info(ip_counts.head())
        
        logger.info(f"\nGenerated {total_requests:,} log entries")
        logger.info(f"Attack requests: {attack_requests:,} "
                   f"({attack_requests/total_requests*100:.1f}%)")
        logger.info("Attack type distribution:")
        for attack_type, count in attack_types.items():
            logger.info(f"  {attack_type}: {count:,} requests")
        logger.info(f"Dataset saved to: {output_path}")

def get_default_attack_config(attack_type: str) -> AttackConfig:
    """Get default configuration for an attack type with randomized parameters."""
    base_configs = {
        'brute_force': {
            'frequency': (80, 200),  # attacks per hour
            'duration': (1, 4),      # hours
            'source_ips': (3, 8),    # number of IPs
            'severity': 'High',
            'target_paths': ['/login', '/auth/login', '/signin', '/admin/login', '/api/v1/auth/login'],
            'payloads': None
        },
        'sql_injection': {
            'frequency': (30, 100),
            'duration': (1, 3),
            'source_ips': (2, 5),
            'severity': 'High',
            'target_paths': ['/search', '/api/v1/users', '/api/v1/products'],
            'payloads': None
        },
        'xss': {
            'frequency': (20, 80),
            'duration': (0.5, 2),
            'source_ips': (1, 4),
            'severity': 'Medium',
            'target_paths': ['/comment', '/api/v1/feedback', '/search'],
            'payloads': None
        },
        'path_traversal': {
            'frequency': (10, 50),
            'duration': (0.5, 2),
            'source_ips': (1, 3),
            'severity': 'Medium',
            'target_paths': ['/download', '/api/v1/files', '/static'],
            'payloads': None
        }
    }
    
    if attack_type not in base_configs:
        raise ValueError(f"Unknown attack type: {attack_type}")
    
    config = base_configs[attack_type]
    return AttackConfig(
        attack_type=attack_type,
        frequency=random.randint(*config['frequency']),
        duration_hours=random.uniform(*config['duration']),
        severity=config['severity'],
        source_ips=random.randint(*config['source_ips']),
        target_paths=config['target_paths'],
        payloads=config['payloads']
    )

def main():
    """Parse command line arguments and generate dataset."""
    parser = argparse.ArgumentParser(
        description='Generate synthetic log data with customizable attack patterns'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='logs/synthetic_logs.log',
        help='Output log file path (default: logs/synthetic_logs.log)'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=float,
        default=24.0,
        help='Duration of log generation in hours (default: 24.0)'
    )
    
    parser.add_argument(
        '--normal-rate', '-n',
        type=int,
        default=1000,
        help='Normal requests per hour (default: 1000)'
    )
    
    parser.add_argument(
        '--attacks', '-a',
        nargs='+',
        choices=['brute_force', 'sql_injection', 'xss', 'path_traversal'],
        help='Types of attacks to include (e.g., brute_force sql_injection)'
    )
    
    parser.add_argument(
        '--list-attacks',
        action='store_true',
        help='List available attack types and their characteristics'
    )
    
    args = parser.parse_args()
    
    if args.list_attacks:
        print("\nAvailable attack types and their characteristics:")
        print("\n1. Brute Force Attack:")
        print("   - High frequency (80-200 attempts/hour)")
        print("   - Duration: 1-4 hours")
        print("   - Multiple source IPs (3-8)")
        print("   - Targets: /login, /admin/login, /api/v1/auth")
        
        print("\n2. SQL Injection Attack:")
        print("   - Medium-high frequency (30-100 attempts/hour)")
        print("   - Duration: 1-3 hours")
        print("   - Multiple source IPs (2-5)")
        print("   - Targets: /search, /api/v1/users, /api/v1/products")
        
        print("\n3. XSS Attack:")
        print("   - Medium frequency (20-80 attempts/hour)")
        print("   - Duration: 0.5-2 hours")
        print("   - Fewer source IPs (1-4)")
        print("   - Targets: /comment, /api/v1/feedback, /search")
        
        print("\n4. Path Traversal Attack:")
        print("   - Low-medium frequency (10-50 attempts/hour)")
        print("   - Duration: 0.5-2 hours")
        print("   - Few source IPs (1-3)")
        print("   - Targets: /download, /api/v1/files, /static")
        return
    
    generator = LogGenerator()
    
    # Parse attack configurations
    attack_configs = []
    if args.attacks:
        for attack_type in args.attacks:
            try:
                attack_config = get_default_attack_config(attack_type)
                attack_configs.append(attack_config)
                logger.info(f"Added {attack_type} attack with frequency {attack_config.frequency}/hour "
                          f"for {attack_config.duration_hours:.1f} hours")
            except ValueError as e:
                logger.error(f"Error configuring attack: {e}")
                return
    else:
        # Use default attack configurations if none specified
        attack_configs = [
            get_default_attack_config('brute_force'),
            get_default_attack_config('sql_injection'),
            get_default_attack_config('xss')
        ]
        logger.info("Using default attack configurations")
    
    # Generate dataset
    generator.generate_dataset(
        duration_hours=args.duration,
        normal_requests_per_hour=args.normal_rate,
        attack_configs=attack_configs,
        output_file=os.path.basename(args.output)
    )

if __name__ == "__main__":
    main() 