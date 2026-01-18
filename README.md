🕵️‍♂️ ForenSight (Python)

ForenSight is a forensic file analysis tool designed for malware triage, incident response, and threat hunting.
It identifies the true nature of files by analyzing content rather than extensions, validates structure, detects polyglots, extracts embedded artifacts, and supports YARA-based detection.

🔍 Features
File Identification & Validation

Content-based detection (magic bytes, not extensions)

Structural validation for PDF, ZIP, PE, ELF, and common image formats

Extension mismatch detection

Polyglot Detection

Detects files that are valid in multiple formats

Flags format confusion and spoofing attempts

Embedded Artifact Extraction

Extracts and hashes PDF streams (best-effort decompression)

Extracts and hashes Office macros (vbaProject.bin) from OOXML documents

SHA-256 hashing for all extracted objects

ZIP Parsing (No Libraries)

Manual End of Central Directory (EOCD) parsing

Central Directory parsing

Local file header extraction

Deflate + stored compression support

Script Heuristics

Detects PowerShell, JavaScript, VBScript, Batch, Python, and Shell scripts

Keyword + structure scoring

Flags suspicious script-like payloads

YARA Integration (Optional)

Supports yara-python

Load rules from file or directory

Clean, structured match output

Automation Friendly

JSON output mode

Safe to use in pipelines and CI

Designed for Linux security environments

📦 Requirements

Python 3.9+

Linux (Kali, Ubuntu, Debian, Arch)

Optional: yara-python

🚀 Installation
Clone the repository
git clone https://github.com/chrisgomez423/ForenSight.git
cd ForenSight

Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

Install optional dependency (YARA)
pip install yara-python

🧪 Usage
Basic scan
python3 forensight.py suspicious.bin

Scan with YARA rules
python3 forensight.py suspicious.bin --yara rules/

JSON output (automation / CI)
python3 forensight.py suspicious.bin --json > report.json

🧬 Examples
Extension mismatch detection
cp /bin/ls fake.pdf
python3 forensight.py fake.pdf

Script detection
echo 'powershell -nop -w hidden -enc ZQB2AGkAbA==' > evil.txt
python3 forensight.py evil.txt

Polyglot detection
cat /bin/ls test.pdf > polyglot.bin
python3 forensight.py polyglot.bin

🧠 Output Example
ForenSight v0.1.0
Target: suspicious.bin
Signature hits: PDF, ZIP
Polyglot: YES
Script heuristics: PowerShell (score=5)
YARA matches: 1
Extracted artifacts: 4
Warnings:
  - polyglot indicators detected
  - extension mismatch

🗂️ Project Structure
ForenSight/
├── forensight.py
├── rules/
│   └── suspicious_strings.yar
├── samples/
│   └── safe_test_files
└── README.md

🔐 YARA Rules

Place YARA rules in the rules/ directory.

Example:

python3 forensight.py file.bin --yara rules/

⚠️ Disclaimer

ForenSight is intended for educational and defensive security use only.
Only scan files you own or have permission to analyze.

📜 License

MIT License — see LICENSE

👤 Author

Chris Gomez
Cybersecurity | Malware Analysis | Detection Engineering
GitHub: https://github.com/chrisgomez423
clean up formatting for GitHub rendering

Just tell me 👌
