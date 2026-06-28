# API Key & Secret Scanner

A command-line tool designed to detect leaked credentials, certificates, and secrets in files and folders using Regex rules and Shannon Entropy analysis.

## 📋 Features

- **Shannon Entropy Analysis**: Calculates string randomness metrics to detect cryptographically strong keys and reduce false positives.
- **Provider Signatures**: Built-in regex matches for common API keys (AWS, Google Cloud, Stripe, Slack, Slack Webhooks, etc.).
- **Directory and File Scans**: Recursively audits files, folders, or specific target directories.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/amooryx/secret-scanner.git
   cd secret-scanner
   ```

2. Install dependencies:
   ```bash
   pip install pathspec
   ```

## 🚀 Usage

Scan a local directory:

```bash
python main.py -p /path/to/source-code
```

Set entropy thresholds (default is 4.5):

```bash
python main.py -p /path/to/source-code --entropy 5.0
```

## 🛡️ Disclaimer

This tool is designed for educational and security compliance auditing purposes only. Ensure you have authorized permission prior to running scans against active environments.
