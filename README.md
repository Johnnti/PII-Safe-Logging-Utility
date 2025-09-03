# Beacon PII-Safe Logger

A self-contained Python module that implements **Beacon-grade privacy and safety safeguards** for application logging.  
It redacts personally identifiable information (PII), enforces consent-aware logging, supports audit levels, and comes with built-in unit tests.

---

## Features

- 🔒 **PII Detection & Redaction**  
  - Emails (`[REDACTED_EMAIL]`)  
  - Phone numbers (`[REDACTED_PHONE]`)  
  - GPS coordinates (`[REDACTED_GPS]`)  
  - Proper names (heuristic)  

- ✅ **Consent-Aware Logging**  
  - Require explicit `require_consent(user_id)` before writing logs.  
  - Support for revoking consent.  
  - System events without a user ID may still be logged.

- ⚙️ **Audit Levels**  
  - `NONE`: suppress all writes  
  - `MINIMAL` *(default)*: event + redacted message + **hashed user ID**  
  - `DIAG`: event + redacted message + structured, redacted fields  

- 🔑 **Safety-by-Default**  
  - Defaults to `MINIMAL` audit level.  
  - User IDs hashed with SHA-256 (first 16 hex chars).  
  - End-to-end redaction of structured fields.

- 🧪 **Unit Tests Included**  
  - Run in-place with `python beacon_pii_safe_logger.py`.  
  - Covers consent gating, audit levels, edge-case redaction, and nested structures.

---

## Installation

Clone this repo or copy `beacon_pii_safe_logger.py` into your project.  
No external dependencies — only uses Python’s standard library.

```bash
git clone https://github.com/your-org/beacon-pii-safe-logger.git
cd beacon-pii-safe-logger
