README.txt
Readme.md

# 🕵️‍♂️ ForenSight (Python)

ForenSight is a forensic file analysis tool designed for malware triage, incident response, and threat hunting.  
It identifies the true nature of files by analyzing content rather than extensions, validates structure, detects polyglots, extracts embedded artifacts, and supports YARA-based detection.

---

## 🔍 Features

### File Identification & Validation
- Content-based detection (magic bytes, not extensions)
- Structural validation for PDF, ZIP, PE, ELF, and common image formats
- Extension mismatch detection

### Polyglot Detection
- Detects files that are valid in multiple formats
- Flags format confusion and spoofing attempts

### Embedded Artifact Extraction
- Extracts and hashes PDF streams (best-effort decompression)
- Extracts and hashes Office macros (`vbaProject.bin`) from OOXML documents
- SHA-256 hashing for all extracted objects

### ZIP Parsing (No Libraries)
- Manual End of Central Directory (EOCD) parsing
- Central Directory parsing
- Local file header extraction
- Deflate + stored compression support

### Script Heuristics
- Detects PowerShell, JavaScript, VBScript, Batch, Python, and Shell scripts
- Keyword + structure scoring
- Flags suspicious script-like payloads

### YARA Integration (Optional)
- Supports `yara-python`
- Load rules from file or directory
- Clean, structured match output

### Automation Friendly
- JSON output mode
- Safe to use in pipelines and CI
- Designed for Linux security environments

---

## 📦 Requirements
- Python 3.9+
- Linux (Kali, Ubuntu, Debian, Arch)
- Optional: `yara-python`

---

## 🚀 Installation

### Clone the repository
```bash
git clone https://github.com/chrisgomez423/ForenSight.git
cd ForenSight
