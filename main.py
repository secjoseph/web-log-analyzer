#!/usr/bin/env python3
import argparse
import logging
import sys
from pathlib import Path
from typing import Optional
import pandas as pd
from colorama import init, Fore, Style
from tqdm import tqdm

from parser import LogParser
from detector import ThreatDetector
from visualizer import LogVisualizer

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('log_analyzer.log')
    ]
)
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Analyze server logs for security threats and generate visualizations.'
    )
    
    parser.add_argument(
        '--log-file',
        type=str,
        required=True,
        help='Path to the log file to analyze'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='reports',
        help='Directory to save reports and visualizations (default: reports)'
    )
    
    parser.add_argument(
        '--alert-file',
        type=str,
        default='alerts.txt',
        help='File to save security alerts (default: alerts.txt)'
    )
    
    parser.add_argument(
        '--save-parsed',
        action='store_true',
        help='Save parsed log data to CSV file'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to custom configuration file (JSON)'
    )
    
    return parser.parse_args()

def save_alerts(alerts: list, filepath: str) -> None:
    """Save security alerts to a file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("Security Alerts Report\n")
        f.write("=" * 50 + "\n\n")
        
        if not alerts:
            f.write("No security alerts detected.\n")
            return
        
        # Group alerts by type
        alerts_by_type = {}
        for alert in alerts:
            if alert.alert_type not in alerts_by_type:
                alerts_by_type[alert.alert_type] = []
            alerts_by_type[alert.alert_type].append(alert)
        
        # Write alerts by type
        for alert_type, type_alerts in alerts_by_type.items():
            f.write(f"\n{alert_type}\n")
            f.write("-" * len(alert_type) + "\n")
            
            for alert in type_alerts:
                f.write(f"\nTimestamp: {alert.timestamp}\n")
                f.write(f"Severity: {alert.severity}\n")
                f.write(f"IP: {alert.ip}\n")
                f.write(f"Description: {alert.description}\n")
                f.write("Details:\n")
                for key, value in alert.details.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")

def print_summary(df: pd.DataFrame, alerts: list) -> None:
    """Print a summary of the analysis to console."""
    print("\n" + "=" * 50)
    print(f"{Fore.CYAN}Analysis Summary{Style.RESET_ALL}")
    print("=" * 50)
    
    # Basic statistics
    print(f"\n{Fore.GREEN}Log Statistics:{Style.RESET_ALL}")
    print(f"Total Requests: {len(df):,}")
    print(f"Unique IPs: {df['ip'].nunique():,}")
    print(f"Time Range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print(f"Error Rate: {(df['status'] >= 400).mean() * 100:.1f}%")
    
    # Alert summary
    print(f"\n{Fore.YELLOW}Security Alerts:{Style.RESET_ALL}")
    if not alerts:
        print("No security alerts detected.")
    else:
        print(f"Total Alerts: {len(alerts)}")
        
        # Count by severity
        severity_counts = {}
        for alert in alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        
        print("\nAlerts by Severity:")
        for severity, count in severity_counts.items():
            color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.GREEN
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        # Count by type
        type_counts = {}
        for alert in alerts:
            type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
        
        print("\nAlerts by Type:")
        for alert_type, count in type_counts.items():
            print(f"  {alert_type}: {count}")
    
    print("\n" + "=" * 50)

def main() -> None:
    """Main entry point for the log analyzer."""
    args = parse_args()
    
    # Validate log file
    log_path = Path(args.log_file)
    if not log_path.exists():
        logger.error(f"Log file not found: {args.log_file}")
        sys.exit(1)
    
    try:
        # Initialize components
        parser = LogParser()
        detector = ThreatDetector()
        visualizer = LogVisualizer(output_dir=args.output_dir)
        
        # Parse log file
        logger.info(f"Parsing log file: {args.log_file}")
        df = parser.parse_file(args.log_file)
        
        if df.empty:
            logger.error("No valid log entries found!")
            sys.exit(1)
        
        # Clean and preprocess data
        logger.info("Cleaning and preprocessing log data...")
        df = parser.clean_data(df)
        
        # Save parsed data if requested
        if args.save_parsed:
            csv_path = Path(args.output_dir) / 'parsed_logs.csv'
            df.to_csv(csv_path, index=False)
            logger.info(f"Saved parsed logs to: {csv_path}")
        
        # Detect threats
        logger.info("Detecting security threats...")
        alerts = detector.detect_threats(df)
        
        # Save alerts
        save_alerts(alerts, args.alert_file)
        logger.info(f"Saved alerts to: {args.alert_file}")
        
        # Generate visualizations and report
        logger.info("Generating visualizations and report...")
        visualizer.generate_html_report(df, alerts)
        
        # Print summary to console
        print_summary(df, alerts)
        
        logger.info("Analysis complete!")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main() 