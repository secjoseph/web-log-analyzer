# Web Log Analyzer - Security Threat Detection Tool

A Python-based security log analysis tool that detects and visualizes various web application attacks including brute force attempts, SQL injections, XSS, and path traversal attacks. It features synthetic log generation, real-time threat detection, and comprehensive attack pattern visualization. While well-structured and easy to use, the tool relies on rule-based detection and lacks advanced techniques like anomaly detection or machine learning. It supports only standard log formats and offers basic visualizations without an interactive dashboard, making it best suited for educational use, lightweight monitoring, or prototyping rather than enterprise-scale deployment.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/secjoseph/web-log-analyzer.git
cd log-analyzer
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Place your log files in the `logs/` directory
2. Run the analyzer:
```bash
python main.py --log-file logs/access.log
```

### Command Line Options

- `--log-file`: Path to the log file to analyze
- `--output`: Output directory for reports (default: ./reports)
- `--alert-file`: Path to save alerts (default: alerts.txt)
- `--visualize`: Generate visualizations (default: True)

### Dataset Generator

The project includes a dataset generator that creates synthetic log data with customizable attack patterns. This is useful for testing and development.

#### Basic Usage

Generate a default dataset with common attack patterns:
```bash
python gen/dataset_generator.py
```

Or use command-line arguments to customize the generation:

```bash
# List available attack types and their characteristics
python gen/dataset_generator.py --list-attacks

# Generate logs with specific attack types
python gen/dataset_generator.py --attacks brute_force sql_injection

# Generate logs with custom parameters
python gen/dataset_generator.py --duration 48 --normal-rate 2000 --output logs/custom.log --attacks xss path_traversal
```

#### Command Line Options

- `--output`, `-o`: Output log file path (default: logs/synthetic_logs.log)
- `--duration`, `-d`: Duration of log generation in hours (default: 24.0)
- `--normal-rate`, `-n`: Normal requests per hour (default: 1000)
- `--attacks`, `-a`: Types of attacks to include (choices: brute_force, sql_injection, xss, path_traversal)
- `--list-attacks`: List available attack types and their characteristics

#### Attack Types

The generator supports the following attack types, each with realistic randomized parameters:

1. **Brute Force Attack**
   - High frequency (80-200 attempts/hour)
   - Duration: 1-4 hours
   - Multiple source IPs (3-8)
   - Targets: /login, /admin/login, /api/v1/auth

2. **SQL Injection Attack**
   - Medium-high frequency (30-100 attempts/hour)
   - Duration: 1-3 hours
   - Multiple source IPs (2-5)
   - Targets: /search, /api/v1/users, /api/v1/products

3. **XSS Attack**
   - Medium frequency (20-80 attempts/hour)
   - Duration: 0.5-2 hours
   - Fewer source IPs (1-4)
   - Targets: /comment, /api/v1/feedback, /search

4. **Path Traversal Attack**
   - Low-medium frequency (10-50 attempts/hour)
   - Duration: 0.5-2 hours
   - Few source IPs (1-3)
   - Targets: /download, /api/v1/files, /static

#### Examples

1. Generate logs with only brute force attacks:
```bash
python gen/dataset_generator.py --attacks brute_force
```

2. Generate logs with multiple attack types:
```bash
python gen/dataset_generator.py --attacks brute_force sql_injection xss
```

3. Generate a large dataset with high traffic:
```bash
python gen/dataset_generator.py --duration 72 --normal-rate 5000 --output logs/large_dataset.log --attacks brute_force sql_injection
```

The generator will automatically randomize attack parameters within realistic ranges to create varied and realistic attack patterns. Each run will produce slightly different attack characteristics while maintaining realistic attack patterns.


## Dependencies

- Python 3.x
- pandas
- matplotlib
- seaborn
- numpy
- python-dateutil


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
