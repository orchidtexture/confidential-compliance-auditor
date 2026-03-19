# 🛡️ Confidential Compliance Auditor (CCA) MVP

The Confidential Compliance Auditor (CCA) is a state-of-the-art platform designed to resolve the **Disclosure-Audit Paradox**. It allows innovators to submit highly sensitive, proprietary data for compliance auditing without ever exposing the raw Intellectual Property (IP) to the auditor, the cloud provider, or the host operating system.

Built on top of the **Dstack SDK** and designed for Trusted Execution Environments (TEEs) like Intel TDX, this MVP implements a cryptographically enforced "Ironclad NDA."

## ✨ Key Architectural Features

1. **Hardware Root of Trust:** Leverages TEE Attestation Quotes to prove the identity and immutability of the auditing logic.
2. **In-Memory Decryption:** Uses X25519 Ephemeral Key Exchange and AES-GCM to decrypt payloads purely in RAM, bypassing disk storage completely.
3. **Stateless Execution:** Replay attacks are mathematically neutralized via strict stateless processing and hardcoded, immutable system prompts.
4. **Pill X Memory Wiping:** Explicitly overwrites mutable bytearrays with zeros and forces garbage collection immediately post-audit to guarantee context destruction.
5. **Categorical Redaction:** The AI auditor is strictly constrained to output only abstracted JSON reports, preventing raw IP leakage.
6. **Cryptographic Certification:** The final sanitized report is hashed (SHA-256) and signed by the TEE hardware, providing mathematical proof of the audit's integrity.

## 🚀 Getting Started

### Prerequisites

* Python 3.13+
* `poetry` for dependency management
* [dstack simulator](https://docs.phala.com/dstack/local-development#simulator) (for running locally)

### 1. Start the CCA Auditor Server

Setup the environmental variables

```bash
export LLM_BASE_URL="https://example.com/v1"
export LLM_API_KEY="sk-proj-some-key"
export LLM_MODEL="gpt-5-"
```

_For the TEE environment this variables should be hardcoded on the `docker-compose.yml`_

To run the auditor locally (our code automatically detects if it's in a real TEE or local dev mode):

```bash
poetry run uvicorn src.cca_poc.main:app --reload
```

*The server will start on `http://0.0.0.0:8000`.*

### 2. Run the End-to-End Client Flow

Open a new terminal window. This script simulates an "Auditee" encrypting their trade secrets, sending them to the enclave, and cryptographically verifying the signed response.

```bash
poetry run python test_cca_flow.py
```

**Expected Output:** You will see the secure handshake, the AES-GCM encryption process, the sanitized JSON report, and the successful local SHA-256 hash verification against the hardware quote.

### 3. Run the Test Suite

We have a comprehensive Pytest suite that validates the entire pipeline, including security rejection of tampered data and stateless immutability checks.

```bash
poetry run pytest -v tests/test_cca.py
```

**Expected Output:** All tests passing, confirming the "Ironclad NDA" is secure and functional.

## How it works?

### Confidential Compliance Auditor (CCA) Pipeline

Architecture & Lifecycle Specification (Updated)

#### Overview

The CCA Pipeline resolves the Disclosure-Audit Paradox by executing compliance checks entirely within a Trusted Execution Environment (TEE). This pipeline emphasizes high scalability, stateless execution, and verifiable memory destruction.

**Phase 1: The "Ironclad" Handshake & Secure Ingestion**
1. **Hardware Root of Trust:** The Auditee requests a connection to the CCA. The TEE Guest Agent generates a hardware-rooted Attestation Quote.
2. **Immutable Logic Verification:** The Attestation Quote includes the hash (MRTD) of the auditor's code. This mathematically proves to the Auditee that the AI's "Reasoning Chain" and system prompts are hardcoded, immutable, and cannot be maliciously altered to extract IP.
3. **Forward Secrecy:** The Auditee generates an ephemeral public key, encrypts their proprietary payload, and transmits it. The raw data is never exposed on the network.

**Phase 2: Purely In-Memory Decryption**
1. **Key Exchange:** The TEE derives its hardware-backed private key and combines it with the Auditee's ephemeral key to establish a shared secret.
2. **Mutable Target:** The payload is decrypted purely in-memory directly into a mutable data structure (e.g., a `bytearray`).
3. **Zero Disk I/O:** At no point during ingestion or decryption does the raw data touch the file system or standard `tmpfs` volumes.

**Phase 3: Stateless Confidential Inference & Categorical Redaction**
1. **Stateless Instantiation:** The LLM compliance auditor is invoked with a strict, single-use context window. No global ledgers or historical session states are maintained, rendering replay attacks ineffective.
2. **Categorical Redaction Rules:** The LLM evaluates the proprietary data against the immutable compliance rules. If a violation is found, the LLM must generate a remediation report using abstract, categorical descriptions (e.g., "Proprietary algorithm detected").
3. **Strict Output Constraints:** The LLM is cryptographically and logically forbidden from quoting, echoing, or directly referencing any specific lines of code, variable names, or raw IP in its output.

**Phase 4: Provable Memory Wiping (The "Pill X" Protocol)**

_To maintain high throughput and scalability, the TEE instance remains alive while mathematically guaranteeing the destruction of the Auditee's data._
1. **Explicit Zeroing:** Immediately after the LLM generates the abstracted JSON response, the application iterates through the mutable `bytearray` containing the decrypted secret, explicitly overwriting every byte with zeros.
2. **Context Annihilation:** All inference arrays, prompt variables, and string copies are explicitly deleted from the application's scope.
3. **Garbage Collection:** A forceful memory sweep is triggered to instantly reclaim the RAM, ensuring no dangling pointers to the secret remain in the TEE's memory.

**Phase 5: Cryptographic Certification & Release**
1. **Hardware Signing:** The abstracted, sanitized JSON report is cryptographically signed (or bound to a new hardware quote) by the Dstack SDK.
2. **Result Release:** The certified report is returned to the Auditee. The Auditee possesses cryptographic proof that their data was audited by the agreed-upon rules and that the raw data no longer exists anywhere in the system.

## 🔐 Security Notice

This is an MVP designed to prove the core "Steel Thread" of the Disclosure-Audit Paradox resolution. For production deployment:

* Deploy strictly within a certified Dstack CVM (Confidential VM).
* Swap the mocked LLM logic in `main.py` with an actual local inference engine (e.g., `vLLM` or `llama.cpp`) running inside the same enclave boundary.