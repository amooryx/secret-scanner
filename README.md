<div align="center">
  <img src="./banner.svg" alt="secret-scanner" width="800">
</div>

# API Key & Secret Scanner

## 📋 Features

- **Provider Signatures**: Detects common AWS, Google, Slack, Stripe, GitHub, JWT, and private-key patterns.
- **Local by default**: A target is read as a local file unless it is an explicit HTTP(S) URL. File names containing dots are not treated as hosts.
- **Secret-safe findings**: Reports finding types and severity without printing matched credential values.
- **Explicit authorization**: Prompts for authorization before scanning; use `--yes` only when authorization is already established.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/amooryx/secret-scanner.git
   cd secret-scanner
   ```

2. No third-party dependencies are required.

## 🚀 Usage

Scan a local file (the default and recommended mode):

```bash
python main.py --yes path/to/config.json
```

Scan a remote page only by providing its full HTTP(S) URL:

```bash
python main.py --yes https://example.com/config
```

The scanner reads remote response content but does not upload local files. Findings and JSON exports contain no matched secret values. This command scans one file or one URL; it does not recursively scan directories or perform entropy analysis.

## 🛡️ Disclaimer

This tool is designed for educational and security compliance auditing purposes only. Ensure you have authorized permission prior to running scans against active environments.
