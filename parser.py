import re
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogParser:
    """Parser for Apache/Nginx access logs."""
    
    # Common log format regex pattern
    COMMON_LOG_PATTERN = r'^(\S+) - - \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+|-) "(.*?)" "(.*?)"$'
    
    def __init__(self):
        self.pattern = re.compile(self.COMMON_LOG_PATTERN)
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line into a dictionary of fields."""
        try:
            match = self.pattern.match(line.strip())
            if not match:
                logger.warning(f"Could not parse line: {line.strip()}")
                return None
            
            ip, timestamp, method, url, protocol, status, size, referer, user_agent = match.groups()
            
            # Convert timestamp to datetime object
            try:
                timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                logger.warning(f"Invalid timestamp format: {timestamp}")
                return None
            
            # Convert status to integer
            try:
                status = int(status)
            except ValueError:
                logger.warning(f"Invalid status code: {status}")
                return None
            
            # Convert size to integer (handle '-' for zero size)
            try:
                size = int(size) if size != '-' else 0
            except ValueError:
                logger.warning(f"Invalid size: {size}")
                return None
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'url': url,
                'protocol': protocol,
                'status': status,
                'size': size,
                'referer': referer,
                'user_agent': user_agent
            }
        except Exception as e:
            logger.error(f"Error parsing line: {str(e)}")
            return None
    
    def parse_file(self, file_path: str) -> pd.DataFrame:
        """Parse a log file into a pandas DataFrame."""
        logger.info(f"Parsing log file: {file_path}")
        
        parsed_lines = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = self.parse_line(line)
                if parsed:
                    parsed_lines.append(parsed)
        
        if not parsed_lines:
            logger.warning("No valid log entries found!")
            return pd.DataFrame()
        
        df = pd.DataFrame(parsed_lines)
        logger.info(f"Successfully parsed {len(df)} log entries")
        return df
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and preprocess the parsed log data."""
        if df.empty:
            return df
        
        # Remove duplicate entries
        df = df.drop_duplicates()
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Add derived columns
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.date
        df['is_error'] = df['status'].apply(lambda x: x >= 400)
        
        # Extract potential attack patterns
        df['suspicious_url'] = df['url'].apply(self._check_suspicious_url)
        df['suspicious_user_agent'] = df['user_agent'].apply(self._check_suspicious_user_agent)
        
        return df
    
    @staticmethod
    def _check_suspicious_url(url: str) -> bool:
        """Check if URL contains suspicious patterns."""
        suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'<script>',  # XSS attempt
            r'exec\(',  # Command injection
            r'\.php\?',  # PHP file access
            r'\.asp\?',  # ASP file access
            r'\.jsp\?',  # JSP file access
            r'\.env',    # Environment file access
            r'\.git',    # Git directory access
            r'\.svn',    # SVN directory access
            r'\.htaccess' # Apache config access
        ]
        
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns)
    
    @staticmethod
    def _check_suspicious_user_agent(user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        suspicious_patterns = [
            r'nmap',  # Network scanner
            r'sqlmap',  # SQL injection tool
            r'nikto',  # Web server scanner
            r'wget',  # Automated download
            r'curl',  # Automated download
            r'python-requests',  # Automated requests
            r'go-http-client',  # Automated requests
            r'java-http-client'  # Automated requests
        ]
        
        return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in suspicious_patterns) 