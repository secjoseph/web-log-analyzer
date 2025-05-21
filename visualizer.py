import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Optional
import logging
from datetime import datetime
import os
from detector import Alert
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogVisualizer:
    """Generates visualizations from log data and alerts."""
    
    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = output_dir
        # Set seaborn theme for better visualization
        sns.set_theme(style="darkgrid", palette="husl")
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_all_visualizations(self, df: pd.DataFrame, alerts: List[Alert]) -> None:
        """Generate all available visualizations."""
        logger.info("Generating visualizations...")
        
        self.plot_request_timeline(df)
        self.plot_status_distribution(df)
        self.plot_top_ips(df)
        self.plot_request_methods(df)
        self.plot_alerts_timeline(alerts)
        self.plot_alert_distribution(alerts)
        
        logger.info(f"Visualizations saved to {self.output_dir}")
    
    def plot_request_timeline(self, df: pd.DataFrame) -> None:
        """Plot request volume over time."""
        plt.figure(figsize=(15, 6))
        
        # Resample to hourly intervals using 'h' instead of deprecated 'H'
        hourly_requests = df.resample('h', on='timestamp').size()
        
        plt.plot(hourly_requests.index, hourly_requests.values, linewidth=2)
        plt.title('Request Volume Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        self._save_plot('request_timeline.png')
    
    def plot_status_distribution(self, df: pd.DataFrame) -> None:
        """Plot distribution of HTTP status codes."""
        plt.figure(figsize=(10, 6))
        
        status_counts = df['status'].value_counts().sort_index()
        
        # Create color mapping
        colors = ['green' if 200 <= x < 300 else
                 'blue' if 300 <= x < 400 else
                 'orange' if 400 <= x < 500 else
                 'red' for x in status_counts.index]
        
        bars = plt.bar(status_counts.index.astype(str), status_counts.values, color=colors)
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}',
                    ha='center', va='bottom')
        
        plt.title('Distribution of HTTP Status Codes')
        plt.xlabel('Status Code')
        plt.ylabel('Count')
        plt.tight_layout()
        
        self._save_plot('status_distribution.png')
    
    def plot_top_ips(self, df: pd.DataFrame, top_n: int = 10) -> None:
        """Plot top IP addresses by request volume."""
        plt.figure(figsize=(12, 6))
        
        ip_counts = df['ip'].value_counts().head(top_n)
        
        bars = plt.barh(ip_counts.index, ip_counts.values)
        plt.title(f'Top {top_n} IP Addresses by Request Volume')
        plt.xlabel('Number of Requests')
        plt.ylabel('IP Address')
        
        # Add value labels with proper spacing
        for bar in bars:
            width = bar.get_width()
            plt.text(width + (width * 0.02),  # Add 2% of width as spacing
                    bar.get_y() + bar.get_height()/2,
                    f'{int(width):,}',
                    ha='left', va='center')
        
        plt.tight_layout()
        
        self._save_plot('top_ips.png')
    
    def plot_request_methods(self, df: pd.DataFrame) -> None:
        """Plot distribution of HTTP request methods."""
        plt.figure(figsize=(8, 6))
        
        method_counts = df['method'].value_counts()
        
        plt.pie(method_counts.values, labels=method_counts.index,
                autopct='%1.1f%%', startangle=90)
        plt.title('Distribution of HTTP Request Methods')
        plt.axis('equal')
        
        self._save_plot('request_methods.png')
    
    def plot_alerts_timeline(self, alerts: List[Alert]) -> None:
        """Plot timeline of security alerts."""
        if not alerts:
            logger.warning("No alerts to visualize")
            return
        
        plt.figure(figsize=(15, 6))
        
        # Convert alerts to DataFrame
        alert_df = pd.DataFrame([
            {
                'timestamp': alert.timestamp,
                'alert_type': alert.alert_type,
                'severity': alert.severity
            }
            for alert in alerts
        ])
        
        # Group by hour and alert type
        alert_counts = alert_df.groupby([
            pd.Grouper(key='timestamp', freq='H'),
            'alert_type'
        ]).size().unstack(fill_value=0)
        
        alert_counts.plot(kind='area', stacked=True, alpha=0.7)
        plt.title('Security Alerts Timeline')
        plt.xlabel('Time')
        plt.ylabel('Number of Alerts')
        plt.legend(title='Alert Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        self._save_plot('alerts_timeline.png')
    
    def plot_alert_distribution(self, alerts: List[Alert]) -> None:
        """Plot distribution of alert types and severities."""
        if not alerts:
            logger.warning("No alerts to visualize")
            return
        
        # Create figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Convert alerts to DataFrame
        alert_df = pd.DataFrame([
            {
                'alert_type': alert.alert_type,
                'severity': alert.severity
            }
            for alert in alerts
        ])
        
        # Plot alert types
        alert_type_counts = alert_df['alert_type'].value_counts()
        alert_type_counts.plot(kind='bar', ax=ax1)
        ax1.set_title('Distribution of Alert Types')
        ax1.set_xlabel('Alert Type')
        ax1.set_ylabel('Count')
        ax1.tick_params(axis='x', rotation=45)
        
        # Plot severities
        severity_counts = alert_df['severity'].value_counts()
        colors = ['red' if s == 'High' else 'orange' if s == 'Medium' else 'yellow'
                 for s in severity_counts.index]
        severity_counts.plot(kind='bar', ax=ax2, color=colors)
        ax2.set_title('Distribution of Alert Severities')
        ax2.set_xlabel('Severity')
        ax2.set_ylabel('Count')
        
        plt.tight_layout()
        
        self._save_plot('alert_distribution.png')
    
    def _save_plot(self, filename: str) -> None:
        """Save the current plot to file."""
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        logger.info(f"Saved plot: {filepath}")
    
    def generate_html_report(self, df: pd.DataFrame, alerts: List[Alert]) -> None:
        """Generate an HTML report with all visualizations and statistics."""
        report_path = os.path.join(self.output_dir, 'report.html')
        
        # Generate all visualizations first
        self.generate_all_visualizations(df, alerts)
        
        # Calculate statistics
        total_requests = len(df)
        unique_ips = df['ip'].nunique()
        error_rate = (df['status'] >= 400).mean() * 100
        avg_response_size = df['size'].mean()
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Log Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
                .stat-card {{ background: #f5f5f5; padding: 20px; border-radius: 5px; text-align: center; }}
                .visualization {{ margin: 20px 0; }}
                .visualization img {{ max-width: 100%; height: auto; }}
                h1, h2 {{ color: #333; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Log Analysis Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>Total Requests</h3>
                        <p>{total_requests:,}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Unique IPs</h3>
                        <p>{unique_ips:,}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Error Rate</h3>
                        <p>{error_rate:.1f}%</p>
                    </div>
                    <div class="stat-card">
                        <h3>Avg Response Size</h3>
                        <p>{avg_response_size:.0f} bytes</p>
                    </div>
                </div>
                
                <h2>Visualizations</h2>
                
                <div class="visualization">
                    <h3>Request Timeline</h3>
                    <img src="request_timeline.png" alt="Request Timeline">
                </div>
                
                <div class="visualization">
                    <h3>Status Code Distribution</h3>
                    <img src="status_distribution.png" alt="Status Distribution">
                </div>
                
                <div class="visualization">
                    <h3>Top IP Addresses</h3>
                    <img src="top_ips.png" alt="Top IPs">
                </div>
                
                <div class="visualization">
                    <h3>Request Methods</h3>
                    <img src="request_methods.png" alt="Request Methods">
                </div>
                
                <div class="visualization">
                    <h3>Alerts Timeline</h3>
                    <img src="alerts_timeline.png" alt="Alerts Timeline">
                </div>
                
                <div class="visualization">
                    <h3>Alert Distribution</h3>
                    <img src="alert_distribution.png" alt="Alert Distribution">
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save HTML report
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {report_path}") 