# HunterOS Phase 1 — Recon Foundation

## 1. Purpose

Phase 1 menyediakan controlled reconnaissance foundation untuk authorized security research.

Recon Engine mengkoordinasikan alur keamanan dan mendelegasikan operasi aktual ke modul khusus (DNS, HTTP). Tidak ada network request yang dilakukan sebelum security gate menyetujui.

## 2. Scope

Fitur yang diimplementasikan:

- Target Validation — validasi target sebelum mencapai Scope Guard
- Scope Guard integration — integrasi dengan ScopeEngine singleton
- Policy integration — integrasi dengan PolicyEngine singleton
- Safe Mode integration — integrasi dengan SafeMode
- DNS metadata recon — lookup rekaman DNS menggunakan socket standard library
- HTTP metadata recon — retrieval metadata HTTP menggunakan urllib standard library
- Asset Inventory — manajemen aset yang ditemukan dengan revalidasi wajib
- Storage — JSON-based storage untuk hasil recon dan aset
- CLI — perintah recon melalui `hunter recon`

## 3. Security Architecture

Urutan resmi:

```
Target Validation
        ↓
Scope Guard
        ↓
Policy Engine
        ↓
Action Validation / Safe Mode
        ↓
Recon
        ↓
Result Normalizer
        ↓
Asset Inventory
        ↓
Storage
```

Alur diimplementasikan di `ReconEngine.execute()` dan `ReconEngine.execute_with_recon()`.

## 4. Security Rules

OUT_OF_SCOPE → BLOCK — tidak ada network request
UNKNOWN → REVIEW — tidak ada network request, butuh review manual
IN_SCOPE → lanjut ke Policy Engine → Safe Mode → Recon

DISCOVERY ≠ AUTHORIZATION — aset yang ditemukan tidak otomatis authorized. Harus melewati Target Validation → Scope Guard → Policy → Safe Mode sebelum digunakan sebagai target.

## 5. DNS Recon

Modul: `hunteros/recon/dns.py`

Record types yang didukung:
- A
- AAAA
- CNAME (melalui alias dari gethostbyname_ex)
- MX (via socket methods)
- NS (via socket methods)
- TXT (via socket methods)

Resource limits:
- timeout: 5 detik (default)
- MAX_RECORDS_PER_TYPE: 100

Tidak melakukan:
- brute-force subdomain enumeration
- wordlist-based discovery

Menggunakan `socket.getaddrinfo()` dan `socket.gethostbyname_ex()` — standard library only.

CLI: `hunter recon dns <target>`

## 6. HTTP Recon

Modul: `hunteros/recon/http.py`

Returs metaatdata melalui HEAD request:
- status_code
- headers
- Content-Type
- Server
- final URL (setelah redirect)
- redirect chain
- content_length

Resource limits:
- connection timeout: 5 detik (default)
- read timeout: 5 detik (default)
- max redirects: 5
- max response size: 1MB
- supported protocols: http, https

Tidak melakukan:
- fuzzing
- parameter injection
- form submission
- authentication attacks
- exploit testing
- vulnerability scanning

Menggunakan `urllib.request` — standard library only.

CLI: `hunter recon http <url>`

## 7. Asset Inventory

Modul: `hunteros/recon/asset_inventory.py`

Lifecycle:
1. DISCOVERED — aset ditemukan melalui DNS/HTTP recon, status: `pending_validation`
2. VALIDATION — `validate_asset()` memanggil Target Validation → Scope Guard → Policy → Safe Mode
3. AUTHORIZATION DECISION — hasil: `validated` / `out_of_scope` / `validation_failed`
4. POSSIBLE USE — hanya aset dengan status `validated` yang boleh digunakan sebagai target

Prinsip: DISCOVERED ≠ AUTHORIZED. Aset yang UNKNOWN atau OUT_OF_SCOPE tidak boleh langsung digunakan sebagai authorized target.

## 8. Storage

Modul: `hunteros/recon/storage.py`

Fitur:
- JSON/JSONL storage untuk hasil recon
- Project isolation — setiap project punya direktori terpisah
- Safe file paths — sanitasi nama project
- Path traversal protection — `_sanitize_name()` memblokir `..`, `/`, `\` dan karakter tidak alfanumerik

Error handling:
- Missing/corrupt file → `None` / empty list
- Jangan crash pada file corrupt

## 9. CLI

Perintah yang tersedia dan terverifikasi berjalan:

```
hunter recon --help      — Show recon help
hunter recon dns <target>   — Perform DNS recon on target
hunter recon http <url>     — Perform HTTP metadata recon on URL
hunter recon assets         — List discovered assets
hunter recon status         — Show recon status
```

Behavior tanpa scope:
- `hunter recon dns example.com` → REVIEW (UNKNOWN, no network)
- `hunter recon http https://example.com` → REVIEW (UNKNOWN, no network)

Ini adalah behavior yang diharapkan — security gate menjaga executor tidak dipanggil sebelum authorization.

## 10. Testing

Total: 115/115 PASS

Test environment: Python 3.14.6, pytest 9.1.1, Android Termux

Test coverage mencakup:
- CLI tests (doctor, config, proyek, scope, policy, recon)
- Scope Engine regression (wildcard, subdomain, edge cases)
- Configuration tests
- Safe Mode tests
- Scope Engine tests
- Policy Engine tests
- Project model & manager tests
- Finding model & manager tests
- Evidence model tests
- Logger tests
- Recon Engine security gate tests
- Target Validation tests
- Recon Models tests
- Asset Security tests (DISCOVERED ≠ AUTHORIZED)
- DNS Recon tests
- HTTP Recon tests
- CLI Recon tests

## 11. Limitations

Phase 1:
- Bukan vulnerability scanner
- Tidak melakukan exploitation
- Tidak melakukan brute force
- Tidak melakukan mass scanning
- Tidak melakukan credential attacks
- Tidak melakukan SQLi/XSS/SSRF/RCE testing
- Tidak melakukan unrestricted subdomain enumeration
- DNS/HTTP recon hanya retrieval metadata, bukan deep analysis

## 12. Termux Usage

Environment yang terverifikasi:

```bash
# Akses project directory
cd ~/hunteros

# Install (development mode)
pip install -e .

# Cek environment
hunter doctor

# CLI recon commands
hunter recon --help
hunter recon dns <target>
hunter recon http <url>
hunter recon assets
hunter recon status

# Jalankan test suite
python -m pytest tests/ -q
```

Catatan Termux:
- Python 3.14.6 tersedia di Termux
- Tidak ada external dependencies — stdlib only
- DNS query localhost berfungsi tanpa Internet
- HTTP request ke external URL memerlukan koneksi Internet (tidak diuji dalam verification ini)
