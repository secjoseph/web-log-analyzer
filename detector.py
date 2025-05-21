import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import logging
from dataclasses import dataclass
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Class for storing alert information."""
    timestamp: datetime
    alert_type: str
    severity: str
    description: str
    ip: str
    details: Dict

class ThreatDetector:
    """Detects various security threats in log data."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {
            'brute_force_threshold': 3,     # Lower threshold to detect more attacks
            'brute_force_window': 60,       # Shorter window (1 minute instead of 5)
            'ddos_threshold': 100,          # Requests per minute
            'scan_threshold': 20,           # 404 errors per minute
            'suspicious_patterns': {
                'xss': [r'<script>', r'javascript:', r'onerror=', r'onload='],
                'sql_injection': [r'UNION', r'SELECT', r'DROP', r'--', r'/*'],
                'path_traversal': [r'\.\./', r'\.\.\\'],
                'command_injection': [r'exec\(', r'system\(', r'eval\(']
            }
        }
        self.alerts: List[Alert] = []
    
    def detect_threats(self, df: pd.DataFrame) -> List[Alert]:
        """Run all threat detection methods on the log data."""
        if df.empty:
            logger.warning("No data to analyze!")
            return []
        
        # Clear previous alerts
        self.alerts = []
        
        # Run all detection methods
        self._detect_brute_force(df)
        self._detect_directory_scanning(df)
        self._detect_ddos(df)
        self._detect_suspicious_patterns(df)
        
        return self.alerts
    
    def _detect_brute_force(self, df: pd.DataFrame) -> None:
        """Detect brute force login attempts."""
        # Focus on failed login attempts (typically POST requests to login endpoints)
        login_attempts = df[
            (df['method'] == 'POST') & 
            (df['status'].isin([401, 403])) &
            (df['url'].str.contains(r'/login|/auth|/signin|/admin/login|/api/v1/auth', case=False, na=False))
        ]
        
        logger.info(f"Found {len(login_attempts)} potential login attempts")
        if login_attempts.empty:
            return
        
        # Log unique IPs and their attempt counts
        ip_counts = login_attempts['ip'].value_counts()
        logger.info(f"Login attempts by IP (top 5):\n{ip_counts.head()}")
        
        # Group by IP and check for rapid failed attempts
        for ip, group in login_attempts.groupby('ip'):
            # Sort by timestamp
            group = group.sort_values('timestamp')
            
            # Use a sliding window to detect bursts of failed attempts
            window_size = timedelta(seconds=self.config['brute_force_window'])
            attempts_in_window = []
            
            for i, row in group.iterrows():
                current_time = row['timestamp']
                window_start = current_time - window_size
                
                # Remove attempts outside the current window
                attempts_in_window = [t for t in attempts_in_window if t >= window_start]
                attempts_in_window.append(current_time)
                
                # If we have enough attempts in the window, generate an alert
                if len(attempts_in_window) >= self.config['brute_force_threshold']:
                    logger.info(f"Detected brute force attempt from {ip}: {len(attempts_in_window)} attempts in {self.config['brute_force_window']} seconds")
                    self.alerts.append(Alert(
                        timestamp=current_time,
                        alert_type='Brute Force Attempt',
                        severity='High',
                        description=f'Multiple failed login attempts from {ip} ({len(attempts_in_window)} attempts in {self.config["brute_force_window"]} seconds)',
                        ip=ip,
                        details={
                            'attempts': len(attempts_in_window),
                            'time_window': self.config['brute_force_window'],
                            'status_codes': group[group['timestamp'].isin(attempts_in_window)]['status'].tolist(),
                            'paths': group[group['timestamp'].isin(attempts_in_window)]['url'].tolist()
                        }
                    ))
                    # Clear the window after alerting to avoid duplicate alerts
                    attempts_in_window = []
        
        # Log summary of brute force detection
        brute_force_alerts = [a for a in self.alerts if a.alert_type == 'Brute Force Attempt']
        logger.info(f"Generated {len(brute_force_alerts)} brute force alerts")
        if brute_force_alerts:
            unique_ips = len(set(a.ip for a in brute_force_alerts))
            logger.info(f"Brute force alerts from {unique_ips} unique IPs")
    
    def _detect_directory_scanning(self, df: pd.DataFrame) -> None:
        """Detect directory scanning attempts (many 404 errors)."""
        # Focus on 404 errors
        not_found = df[df['status'] == 404]
        
        if not_found.empty:
            return
        
        # Group by IP and time window (1 minute)
        for ip, group in not_found.groupby('ip'):
            # Resample to 1-minute windows
            group['minute'] = group['timestamp'].dt.floor('min')
            requests_per_minute = group.groupby('minute').size()
            
            # Check for high rate of 404s
            suspicious_minutes = requests_per_minute[
                requests_per_minute >= self.config['scan_threshold']
            ]
            
            for minute, count in suspicious_minutes.items():
                self.alerts.append(Alert(
                    timestamp=minute,
                    alert_type='Directory Scanning',
                    severity='Medium',
                    description=f'Possible directory scanning from {ip}',
                    ip=ip,
                    details={
                        '404_count': count,
                        'urls': group[group['minute'] == minute]['url'].tolist()
                    }
                ))
    
    def _detect_ddos(self, df: pd.DataFrame) -> None:
        """Detect potential DDoS attacks (high request rate)."""
        # Group by IP and time window (1 minute)
        df['minute'] = df['timestamp'].dt.floor('min')
        requests_per_ip = df.groupby(['ip', 'minute']).size().reset_index(name='count')
        
        # Check for high request rates
        suspicious_ips = requests_per_ip[
            requests_per_ip['count'] >= self.config['ddos_threshold']
        ]
        
        for _, row in suspicious_ips.iterrows():
            self.alerts.append(Alert(
                timestamp=row['minute'],
                alert_type='Possible DDoS',
                severity='High',
                description=f'High request rate from {row["ip"]}',
                ip=row['ip'],
                details={
                    'requests_per_minute': row['count'],
                    'threshold': self.config['ddos_threshold']
                }
            ))
    
    def _detect_suspicious_patterns(self, df: pd.DataFrame) -> None:
        """Detect suspicious patterns in URLs and user agents."""
        for pattern_type, patterns in self.config['suspicious_patterns'].items():
            # Check URLs
            suspicious_urls = df[
                df['url'].str.contains('|'.join(patterns), case=False, na=False)
            ]
            
            for _, row in suspicious_urls.iterrows():
                self.alerts.append(Alert(
                    timestamp=row['timestamp'],
                    alert_type=f'Suspicious {pattern_type.upper()} Pattern',
                    severity='High',
                    description=f'Suspicious {pattern_type} pattern detected in URL',
                    ip=row['ip'],
                    details={
                        'url': row['url'],
                        'pattern_type': pattern_type,
                        'method': row['method']
                    }
                ))
    
    def get_alerts_summary(self) -> Dict:
        """Get a summary of detected alerts."""
        if not self.alerts:
            return {'total_alerts': 0}
        
        summary = {
            'total_alerts': len(self.alerts),
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'alerts_by_ip': defaultdict(int)
        }
        
        for alert in self.alerts:
            summary['alerts_by_type'][alert.alert_type] += 1
            summary['alerts_by_severity'][alert.severity] += 1
            summary['alerts_by_ip'][alert.ip] += 1
        
        return dict(summary) 