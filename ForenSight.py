#!/usr/bin/env python3
"""
ForenSight — forensic file identification, polyglot detection, and artifact extraction.

Features:
- Magic-byte + structural validation (PDF/PNG/JPEG/GIF/ZIP/PE/ELF)
- Script heuristics (PowerShell/JS/VBS/Batch/Python)
- Real ZIP parsing (EOCD + Central Directory) without zipfile
- Polyglot detection (multiple validated types)
- Artifact extraction + hashing:
    * PDF streams (raw + best-effort inflate)
    * OOXML macros (vbaProject.bin) extracted from ZIP entries
- Optional YARA scanning (yara-python)
"""

from __future__ import annotations

import os
import re
import math
import json
import zlib
import hashlib
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any

FORENSIGHT_VERSION = "0.1.0"


# -----------------------------
# Basic utilities
# -----------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def is_mostly_text(b: bytes, sample: int = 8192) -> bool:
    chunk = b[:sample]
    if not chunk:
        return False
    bad = 0
    for x in chunk:
        if x in (9, 10, 13):  # \t \n \r
            continue
        if 32 <= x <= 126:
            continue
        # tolerate common UTF-8 lead bytes
        if x >= 0xC0:
            continue
        bad += 1
    return (bad / len(chunk)) < 0.05


def read_range(path: str, start: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(length)


# -----------------------------
# Signatures (magic bytes)
# -----------------------------
@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    offset: int = 0
    kind: str = "prefix"  # exact/prefix
    mime: str = "application/octet-stream"


SIGS = [
    Signature("PDF", b"%PDF-", 0, "prefix", "application/pdf"),
    Signature("PNG", bytes.fromhex("89504E470D0A1A0A"), 0, "exact", "image/png"),
    Signature("JPEG", bytes.fromhex("FFD8FF"), 0, "prefix", "image/jpeg"),
    Signature("GIF", b"GIF87a", 0, "exact", "image/gif"),
    Signature("GIF", b"GIF89a", 0, "exact", "image/gif"),
    Signature("ZIP", bytes.fromhex("504B0304"), 0, "exact", "application/zip"),
    Signature("PE", b"MZ", 0, "prefix", "application/vnd.microsoft.portable-executable"),
    Signature("ELF", bytes.fromhex("7F454C46"), 0, "exact", "application/x-elf"),
]


def match_signatures(data: bytes) -> List[Signature]:
    hits = []
    for s in SIGS:
        start = s.offset
        end = start + len(s.magic)
        if end > len(data):
            continue
        chunk = data[start:end]
        if s.kind == "exact" and chunk == s.magic:
            hits.append(s)
        elif s.kind == "prefix" and chunk.startswith(s.magic):
            hits.append(s)
    return hits


# -----------------------------
# Deep validators (anti-spoof)
# -----------------------------
def validate_pe(data: bytes) -> Tuple[bool, List[str]]:
    notes = []
    if not data.startswith(b"MZ"):
        return False, ["missing MZ"]
    if len(data) < 0x40:
        return False, ["too small for DOS header"]
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew <= 0 or e_lfanew + 4 > len(data):
        return False, [f"invalid e_lfanew {e_lfanew}"]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return False, ["missing PE\\0\\0 signature"]
    notes.append(f"PE signature OK at 0x{e_lfanew:X}")
    return True, notes


def validate_elf(data: bytes) -> Tuple[bool, List[str]]:
    if not data.startswith(bytes.fromhex("7F454C46")):
        return False, ["bad ELF magic"]
    cls = data[4] if len(data) > 4 else 0
    cls_s = "32-bit" if cls == 1 else "64-bit" if cls == 2 else f"unknown({cls})"
    return True, [f"ELF class: {cls_s}"]


def validate_pdf_basic(data: bytes) -> Tuple[bool, List[str]]:
    if not data.startswith(b"%PDF-"):
        return False, ["missing %PDF-"]
    tail = data[-4096:] if len(data) > 4096 else data
    notes = []
    if b"%%EOF" in tail:
        notes.append("found %%EOF near end")
    else:
        notes.append("no %%EOF in last 4KB (may be truncated)")
    return True, notes


def validate_png(data: bytes) -> Tuple[bool, List[str]]:
    if not data.startswith(bytes.fromhex("89504E470D0A1A0A")):
        return False, ["bad PNG signature"]
    if len(data) >= 16 and data[12:16] == b"IHDR":
        return True, ["IHDR present"]
    return False, ["IHDR missing/invalid"]


def validate_jpeg(data: bytes) -> Tuple[bool, List[str]]:
    if not data.startswith(bytes.fromhex("FFD8FF")):
        return False, ["bad JPEG SOI"]
    notes = []
    if data.endswith(bytes.fromhex("FFD9")):
        notes.append("EOI marker present (FFD9)")
    else:
        notes.append("missing EOI marker (may be truncated)")
    return True, notes


def validate_gif(data: bytes) -> Tuple[bool, List[str]]:
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return True, ["valid GIF header"]
    return False, ["bad GIF header"]


# -----------------------------
# Script detection heuristics
# -----------------------------
SCRIPT_RULES: Dict[str, List[bytes]] = {
    "PowerShell": [
        b"powershell", b"invoke-", b"iex", b"new-object", b"frombase64string",
        b"set-executionpolicy", b"downloadstring", b"webclient", b"add-mppreference",
        b"start-process", b"bypass", b"hidden", b"nop", b"-enc"
    ],
    "JavaScript": [
        b"function", b"eval(", b"atob(", b"btoa(", b"document.", b"window.",
        b"xmlhttprequest", b"fetch(", b"require(", b"module.exports", b"process.env"
    ],
    "VBScript": [
        b"createobject(", b"wscript.", b"getobject(", b"on error resume next",
        b"execute(", b"shell("
    ],
    "Batch": [b"@echo off", b"set ", b"if ", b"goto ", b"cmd.exe", b"powershell"],
    "Python": [b"import ", b"def ", b"class ", b"__name__", b"#!/usr/bin/env python"],
    "Shell": [b"#!/bin/sh", b"#!/bin/bash", b"curl ", b"wget ", b"chmod +x", b"/dev/tcp/"],
}


def detect_script_type(data: bytes) -> Optional[Dict[str, Any]]:
    if not is_mostly_text(data):
        return None
    lower = data[:200_000].lower()
    scores: Dict[str, int] = {}
    for lang, keys in SCRIPT_RULES.items():
        score = 0
        for k in keys:
            if k in lower:
                score += 1
        if score:
            scores[lang] = score

    shebang = data[:128]
    if shebang.startswith(b"#!"):
        sb = shebang.lower()
        if b"python" in sb:
            scores["Python"] = scores.get("Python", 0) + 3
        if b"node" in sb or b"javascript" in sb:
            scores["JavaScript"] = scores.get("JavaScript", 0) + 3
        if b"bash" in sb or b"/sh" in sb:
            scores["Shell"] = scores.get("Shell", 0) + 3

    if not scores:
        return None

    best_lang, best_score = max(scores.items(), key=lambda x: x[1])
    return {"detected_script": best_lang, "score": best_score, "all_scores": scores}


# -----------------------------
# ZIP parsing (no zipfile)
# EOCD -> Central Directory -> Local File Headers -> Extract entry bytes
# -----------------------------
ZIP_EOCD_SIG = b"PK\x05\x06"
ZIP_CEN_SIG = b"PK\x01\x02"
ZIP_LOC_SIG = b"PK\x03\x04"


@dataclass
class ZipEntry:
    name: str
    comp_method: int
    comp_size: int
    uncomp_size: int
    local_header_offset: int


def find_eocd(fbytes: bytes) -> Optional[int]:
    window = fbytes[-65557:] if len(fbytes) > 65557 else fbytes
    idx = window.rfind(ZIP_EOCD_SIG)
    if idx < 0:
        return None
    return len(fbytes) - len(window) + idx


def parse_zip_entries(path: str) -> Tuple[bool, List[str], List[ZipEntry]]:
    notes: List[str] = []
    size = os.path.getsize(path)

    # For a portfolio tool, we cap total read to keep memory sane.
    # (ZIP parsing is easiest with random-access; EOCD is near the end.)
    max_read = 25_000_000
    with open(path, "rb") as f:
        if size <= max_read:
            full = f.read()
        else:
            # If large, read the tail only (EOCD scan) and try to parse central dir region if within tail.
            # This may be incomplete on huge archives, but still useful for triage.
            f.seek(max(0, size - 2_000_000))
            full = f.read()
            notes.append("large file: partial read (ZIP parsing may be incomplete)")

    eocd_off = find_eocd(full)
    if eocd_off is None:
        return False, ["EOCD not found (not a valid ZIP or truncated)"], []

    if eocd_off + 22 > len(full):
        return False, ["EOCD truncated"], []

    total_entries = int.from_bytes(full[eocd_off + 10:eocd_off + 12], "little")
    cd_size = int.from_bytes(full[eocd_off + 12:eocd_off + 16], "little")
    cd_off = int.from_bytes(full[eocd_off + 16:eocd_off + 20], "little")

    notes.append(
        f"EOCD at 0x{eocd_off:X}, central_dir_off=0x{cd_off:X}, size={cd_size}, entries={total_entries}"
    )

    entries: List[ZipEntry] = []
    # If partial-read, cd_off may not be in buffer. We'll attempt only if present.
    if cd_off < 0 or cd_off >= len(full):
        notes.append("central directory offset not present in read buffer")
        return True, notes, entries

    i = cd_off
    end = min(cd_off + cd_size, len(full))
    parsed = 0

    while i + 46 <= end and parsed < max(total_entries, 1):
        if full[i:i + 4] != ZIP_CEN_SIG:
            break

        comp_method = int.from_bytes(full[i + 10:i + 12], "little")
        comp_size = int.from_bytes(full[i + 20:i + 24], "little")
        uncomp_size = int.from_bytes(full[i + 24:i + 28], "little")
        name_len = int.from_bytes(full[i + 28:i + 30], "little")
        extra_len = int.from_bytes(full[i + 30:i + 32], "little")
        comment_len = int.from_bytes(full[i + 32:i + 34], "little")
        lho = int.from_bytes(full[i + 42:i + 46], "little")

        name_start = i + 46
        name_end = name_start + name_len
        if name_end > len(full):
            break
        name = full[name_start:name_end].decode("utf-8", errors="replace")

        entries.append(ZipEntry(name, comp_method, comp_size, uncomp_size, lho))
        parsed += 1
        i = name_end + extra_len + comment_len

    if not entries:
        notes.append("no central directory entries parsed (might be partial-read or malformed ZIP)")
    return True, notes, entries


def extract_zip_entry(path: str, entry: ZipEntry) -> Tuple[bool, str, bytes]:
    with open(path, "rb") as f:
        f.seek(entry.local_header_offset)
        lh = f.read(30)
        if len(lh) < 30 or lh[0:4] != ZIP_LOC_SIG:
            return False, "bad local header signature", b""

        name_len = int.from_bytes(lh[26:28], "little")
        extra_len = int.from_bytes(lh[28:30], "little")
        f.read(name_len + extra_len)  # skip filename + extra
        comp = f.read(entry.comp_size)

    if entry.comp_method == 0:
        return True, "stored", comp
    if entry.comp_method == 8:
        try:
            data = zlib.decompress(comp, -zlib.MAX_WBITS)  # raw deflate
            return True, "deflate(raw)", data
        except zlib.error:
            try:
                data = zlib.decompress(comp)
                return True, "deflate(zlib)", data
            except zlib.error:
                return False, "deflate decompress failed", b""
    return False, f"unsupported compression method {entry.comp_method}", b""


def guess_ooxml_type(entry_names: List[str]) -> Optional[str]:
    s = set(entry_names)
    if "word/document.xml" in s:
        return "DOCX (OOXML)"
    if "xl/workbook.xml" in s:
        return "XLSX (OOXML)"
    if "ppt/presentation.xml" in s:
        return "PPTX (OOXML)"
    return None


# -----------------------------
# PDF embedded stream extraction + hashing
# -----------------------------
STREAM_RE = re.compile(br"\bstream\r?\n(.*?)\r?\nendstream\b", re.DOTALL)


def extract_pdf_streams(data: bytes, max_streams: int = 50) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if not data.startswith(b"%PDF-"):
        return results

    for idx, m in enumerate(STREAM_RE.finditer(data)):
        if idx >= max_streams:
            break
        raw = m.group(1)
        item: Dict[str, Any] = {
            "kind": "pdf_stream",
            "index": idx,
            "raw_len": len(raw),
            "raw_sha256": sha256(raw),
        }

        decompressed: Optional[bytes] = None
        try:
            decompressed = zlib.decompress(raw)
        except zlib.error:
            try:
                decompressed = zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                decompressed = None

        if decompressed:
            item["inflated_len"] = len(decompressed)
            item["inflated_sha256"] = sha256(decompressed)
            if is_mostly_text(decompressed):
                item["inflated_text_snippet"] = decompressed[:200].decode("utf-8", errors="replace")

        results.append(item)

    return results


# -----------------------------
# OOXML macro extraction (vbaProject.bin)
# -----------------------------
def extract_ooxml_macros(path: str, entries: List[ZipEntry]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    targets = [e for e in entries if e.name.lower().endswith("vbaproject.bin")]
    for e in targets[:10]:
        ok, method, blob = extract_zip_entry(path, e)
        out.append({
            "kind": "ooxml_vbaProject",
            "entry_name": e.name,
            "ok": ok,
            "method": method,
            "len": len(blob) if ok else 0,
            "sha256": sha256(blob) if ok else None,
        })
    return out


# -----------------------------
# YARA support (optional)
# -----------------------------
def yara_scan(data: bytes, rules_path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not rules_path:
        return None
    try:
        import yara  # type: ignore
    except Exception:
        return {"enabled": False, "error": "yara-python not installed"}

    try:
        if os.path.isdir(rules_path):
            filemap = {}
            for root, _, files in os.walk(rules_path):
                for fn in files:
                    if fn.lower().endswith((".yar", ".yara")):
                        fp = os.path.join(root, fn)
                        filemap[fp] = fp
            if not filemap:
                return {"enabled": True, "matches": [], "note": "no .yar/.yara files found in directory"}
            rules = yara.compile(filepaths=filemap)
        else:
            rules = yara.compile(filepath=rules_path)

        matches = rules.match(data=data)
        cleaned = [{
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
        } for m in matches]

        return {"enabled": True, "match_count": len(cleaned), "matches": cleaned}
    except Exception as e:
        return {"enabled": True, "error": repr(e)}


# -----------------------------
# Main analysis/report
# -----------------------------
@dataclass
class Report:
    tool: str
    version: str
    path: str
    size: int
    extension: str
    entropy: float
    signature_hits: List[str]
    validated_types: List[Dict[str, Any]]
    polyglot: bool
    detected_script: Optional[Dict[str, Any]]
    zip_info: Optional[Dict[str, Any]]
    extracted_artifacts: List[Dict[str, Any]]
    yara: Optional[Dict[str, Any]]
    warnings: List[str]


def analyze(path: str, yara_rules: Optional[str] = None) -> Report:
    size = os.path.getsize(path)
    ext = os.path.splitext(path.lower())[1]

    max_read = 25_000_000
    with open(path, "rb") as f:
        data = f.read(min(size, max_read))

    ent = shannon_entropy(data[:200_000])
    hits = match_signatures(data)
    hit_names = [h.name for h in hits]

    warnings: List[str] = []

    # Validate all matched signatures (polyglot support)
    validated: List[Dict[str, Any]] = []
    for h in hits:
        ok = False
        notes: List[str] = []
        if h.name == "PE":
            ok, notes = validate_pe(data)
        elif h.name == "ELF":
            ok, notes = validate_elf(data)
        elif h.name == "PDF":
            ok, notes = validate_pdf_basic(data)
        elif h.name == "PNG":
            ok, notes = validate_png(data)
        elif h.name == "JPEG":
            ok, notes = validate_jpeg(data)
        elif h.name == "GIF":
            ok, notes = validate_gif(data)
        elif h.name == "ZIP":
            ok, notes = (True, ["ZIP local header matched; EOCD validation pending"])
        validated.append({"type": h.name, "mime": h.mime, "valid": ok, "notes": notes})

    # Script detection
    script = detect_script_type(data)

    # ZIP parsing + OOXML detection + macro extraction
    zip_info = None
    extracted: List[Dict[str, Any]] = []

    is_zip_sig = any(h.name == "ZIP" for h in hits) or data.startswith(ZIP_LOC_SIG)
    if is_zip_sig:
        ok, notes, entries = parse_zip_entries(path)
        entry_names = [e.name for e in entries]
        ooxml = guess_ooxml_type(entry_names) if entries else None

        zip_info = {
            "valid_zip": ok,
            "notes": notes,
            "entry_count": len(entries),
            "ooxml_guess": ooxml,
            "top_entries_sample": entry_names[:25],
        }

        if not ok:
            warnings.append("ZIP signature present but EOCD/central directory parsing failed (possible spoof or truncation)")
        else:
            extracted.extend(extract_ooxml_macros(path, entries))

    # PDF stream extraction
    if any(h.name == "PDF" for h in hits) or data.startswith(b"%PDF-"):
        extracted.extend(extract_pdf_streams(data))

    # YARA scan (optional)
    yara_res = yara_scan(data, yara_rules)

    # Polyglot detection: multiple validated types
    valid_types = [v for v in validated if v["valid"]]
    polyglot = len({v["type"] for v in valid_types}) >= 2
    if polyglot:
        warnings.append("polyglot indicators: multiple valid formats detected")

    # Entropy hints
    if ent >= 7.2:
        warnings.append(f"high entropy ({ent:.2f}) may indicate packing/encryption")
    elif ent <= 2.5 and size > 1024:
        warnings.append(f"very low entropy ({ent:.2f}) suggests mostly text/repetitive data")

    # Extension mismatch (light)
    if hits and ext:
        primary = hits[0].name
        if primary == "PE" and ext not in (".exe", ".dll", ".sys"):
            warnings.append(f"extension mismatch: ext={ext} but content looks like PE")
        if primary == "PDF" and ext not in (".pdf",):
            warnings.append(f"extension mismatch: ext={ext} but content looks like PDF")
        if primary == "ZIP" and ext not in (".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
            warnings.append(f"extension mismatch: ext={ext} but content looks like ZIP/OOXML")

    return Report(
        tool="ForenSight",
        version=FORENSIGHT_VERSION,
        path=path,
        size=size,
        extension=ext,
        entropy=ent,
        signature_hits=hit_names,
        validated_types=validated,
        polyglot=polyglot,
        detected_script=script,
        zip_info=zip_info,
        extracted_artifacts=extracted,
        yara=yara_res,
        warnings=warnings,
    )


# -----------------------------
# CLI
# -----------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        prog="forensight",
        description="ForenSight — forensic file identification, polyglot detection, artifact extraction, and YARA scanning."
    )
    ap.add_argument("path", help="Path to file")
    ap.add_argument("--yara", help="Path to .yar/.yara file or directory", default=None)
    ap.add_argument("--json", help="Output JSON only", action="store_true")
    ap.add_argument("--version", action="store_true", help="Print ForenSight version and exit")
    args = ap.parse_args()

    if args.version:
        print(f"ForenSight v{FORENSIGHT_VERSION}")
        return

    rep = analyze(args.path, yara_rules=args.yara)
    d = asdict(rep)

    if args.json:
        print(json.dumps(d, indent=2))
        return

    print(f"\nForenSight v{FORENSIGHT_VERSION}")
    print(f"Target: {rep.path}")
    print(f"Size: {rep.size} bytes | Ext: {rep.extension or '(none)'} | Entropy: {rep.entropy:.2f}")
    print(f"Signature hits: {', '.join(rep.signature_hits) if rep.signature_hits else '(none)'}")
    print(f"Polyglot: {'YES' if rep.polyglot else 'no'}")

    print("\nValidated types:")
    for v in rep.validated_types:
        status = "VALID" if v["valid"] else "invalid"
        print(f"  - {v['type']} ({status}) :: {v['mime']}")
        for n in v["notes"]:
            print(f"      * {n}")

    if rep.detected_script:
        s = rep.detected_script
        print(f"\nScript heuristics: {s['detected_script']} (score={s['score']})")
        top = sorted(s["all_scores"].items(), key=lambda x: x[1], reverse=True)[:4]
        print("  Scores:", ", ".join([f"{k}={v}" for k, v in top]))

    if rep.zip_info:
        zi = rep.zip_info
        print(f"\nZIP info: valid={zi['valid_zip']} entries={zi['entry_count']}")
        if zi.get("ooxml_guess"):
            print(f"  OOXML guess: {zi['ooxml_guess']}")
        for n in zi["notes"][:6]:
            print(f"  - {n}")

    if rep.yara:
        if rep.yara.get("enabled") is False:
            print("\nYARA: disabled (install yara-python)")
        elif rep.yara.get("error"):
            print(f"\nYARA error: {rep.yara['error']}")
        else:
            print(f"\nYARA matches: {rep.yara.get('match_count', 0)}")
            for m in rep.yara.get("matches", [])[:10]:
                tags = ",".join(m.get("tags", []))
                print(f"  - {m['rule']} [{tags}]")

    if rep.extracted_artifacts:
        print(f"\nExtracted artifacts (hashed): {len(rep.extracted_artifacts)}")
        for a in rep.extracted_artifacts[:12]:
            if a["kind"] == "ooxml_vbaProject":
                print(f"  - OOXML macro: {a['entry_name']} ok={a['ok']} sha256={a['sha256']}")
            elif a["kind"] == "pdf_stream":
                line = f"  - PDF stream #{a['index']} raw_len={a['raw_len']} raw_sha256={a['raw_sha256']}"
                if a.get("inflated_sha256"):
                    line += f" inflated_len={a['inflated_len']} inflated_sha256={a['inflated_sha256']}"
                print(line)

    if rep.warnings:
        print("\nWarnings:")
        for w in rep.warnings:
            print(f"  - {w}")

    print("")


if __name__ == "__main__":
    main()