# 🛡️ Confidential Compliance Auditor (CCA)

The Confidential Compliance Auditor (CCA) is a state-of-the-art platform designed to resolve the **Disclosure-Audit Paradox**. It allows innovators to submit highly sensitive, proprietary data for compliance auditing without ever exposing the raw Intellectual Property (IP) to the auditor, the cloud provider, or the host operating system.

Built on top of the **Dstack SDK** and hosted on **Phala Network's Intel TDX Confidential VMs**, this MVP implements a cryptographically enforced "Ironclad NDA."

## ✨ Key Architectural Features

1. **Hardware Root of Trust:** Leverages TEE Attestation Quotes to prove the identity, configuration, and immutability of the auditing logic.
2. **In-Memory Decryption:** Uses X25519 Ephemeral Key Exchange and AES-GCM to decrypt payloads purely in RAM, bypassing disk storage completely.
3. **Enclave-to-Enclave AI Inference:** Routes the decrypted data via a secure TLS tunnel directly to Phala's hardware-isolated Private AI, eliminating the need to host expensive local LLM sidecars while maintaining strict TEE-level security.
4. **Stateless Execution:** Replay attacks are mathematically neutralized via strict stateless processing and hardcoded, immutable system prompts.
5. **Pill X Memory Wiping:** Explicitly overwrites mutable bytearrays with zeros and forces garbage collection immediately post-audit to guarantee context destruction.
6. **Categorical Redaction:** The AI auditor is strictly constrained to output only abstracted JSON reports, preventing raw IP leakage.
7. **Cryptographic Certification:** The final sanitized report is hashed (SHA-256) and signed by the TEE hardware, providing mathematical proof of the audit's integrity.

## 🚀 Getting Started

### Prerequisites

* Python 3.13+
* `poetry` for dependency management
* [dstack simulator](https://docs.phala.com/dstack/local-development#simulator) (for running locally)

### 1. Start the CCA Auditor Server

Set up the environment variables. During local development, these point to your desired API. In production, the Enclave points to Phala's Private AI.

```bash
export LLM_BASE_URL="https://api.redpill.ai/v1"
export LLM_API_KEY="sk-some-api-key"
export LLM_MODEL="openai/gpt-oss-20b"

```

*Note: For the TEE environment, `LLM_BASE_URL` and `LLM_MODEL` should be hardcoded in the `docker-compose.yml` to be mathematically hashed into the enclave's quote. However, `LLM_API_KEY` must be injected dynamically using Dstack's Encrypted Secrets vault.*

To run the auditor locally (our code automatically detects if it's in a real TEE or local dev mode):

```bash
poetry run uvicorn src.cca_poc.main:app --reload

```

*The server will start on `http://0.0.0.0:8000`.*

### 2. Run the End-to-End Client Flow

Open a new terminal window. This script simulates an "Auditee" encrypting their trade secrets, verifying the enclave's configuration, sending the data, and cryptographically verifying the signed response.

```bash
poetry run python test_cca_flow.py

```

**Expected Output:** You will see the secure handshake, the compose_hash verification, the AES-GCM encryption process, the sanitized JSON report, and the successful local SHA-256 hash verification against the hardware quote.

### 3. Run the Test Suite

We have a comprehensive Pytest suite that validates the entire pipeline, including security rejection of tampered data and stateless immutability checks via mocked Dstack and LLM interfaces.

```bash
poetry run pytest -v tests/test_cca.py

```

**Expected Output:** All tests passing, confirming the "Ironclad NDA" is secure and functional.

## How it works

### Confidential Compliance Auditor (CCA) Pipeline

Architecture & Lifecycle Specification

#### Overview

The CCA Pipeline resolves the Disclosure-Audit Paradox by executing compliance checks entirely within a Trusted Execution Environment (TEE). This pipeline emphasizes high scalability, stateless execution, and verifiable memory destruction.

**Phase 1: The "Ironclad" Handshake & Secure Ingestion**

1. **Hardware Root of Trust:** The Auditee requests a connection to the CCA. The TEE Guest Agent generates a hardware-rooted Attestation Quote.
2. **Immutable Logic & Configuration Verification:** The Attestation Quote includes the hash (MRTD) of the auditor's code and its deployment configuration (`compose_hash`). This mathematically proves that the AI prompts are hardcoded, and the network routing is locked to the secure Private AI endpoint.
3. **Forward Secrecy:** The Auditee generates an ephemeral public key, encrypts their proprietary payload, and transmits it.

**Phase 2: Purely In-Memory Decryption**

1. **Key Exchange:** The TEE derives its hardware-backed private key and combines it with the Auditee's ephemeral key to establish a shared secret.
2. **Mutable Target:** The payload is decrypted purely in-memory directly into a mutable data structure (e.g., a `bytearray`).
3. **Zero Disk I/O:** At no point during ingestion or decryption does the raw data touch the file system or standard `tmpfs` volumes.

**Phase 3: Enclave-to-Enclave Inference & Categorical Redaction**

1. **Secure TEE-to-TEE Connection:** The decrypted data and immutable prompt are sent via a strict TLS tunnel to Phala's Private AI Inference enclave.
2. **Categorical Redaction Rules:** The LLM evaluates the proprietary data against the immutable compliance rules. If a violation is found, the LLM generates a remediation report using abstract, categorical descriptions (e.g., "Proprietary algorithm detected").
3. **Strict Output Constraints:** The LLM is cryptographically and logically forbidden from quoting, echoing, or directly referencing any specific lines of code, variable names, or raw IP in its output.

**Phase 4: Provable Memory Wiping (The "Pill X" Protocol)**

*To maintain high throughput and scalability, the TEE instance remains alive while mathematically guaranteeing the destruction of the Auditee's data.*

1. **Explicit Zeroing:** Immediately after the LLM generates the abstracted JSON response, the application iterates through the mutable `bytearray` containing the decrypted secret, explicitly overwriting every byte with zeros.
2. **Context Annihilation:** All inference arrays, prompt strings, and raw LLM response variables are explicitly deleted from the application's scope.
3. **Garbage Collection:** A forceful memory sweep is triggered to instantly reclaim the RAM, ensuring no dangling pointers to the secret remain in the TEE's memory.

**Phase 5: Cryptographic Certification & Release**

1. **Hardware Signing:** The abstracted, sanitized JSON report is deterministically hashed and cryptographically signed (or bound to a new hardware quote) by the Dstack SDK.
2. **Result Release:** The certified report is returned to the Auditee. The Auditee possesses cryptographic proof that their data was audited by the agreed-upon rules, in a verified environment, and that the raw data no longer exists.

## 🔐 Security Notice

This is a production-ready MVP designed to prove the core "Steel Thread" of the Disclosure-Audit Paradox resolution. When deploying to Phala Cloud:

* Ensure `LLM_BASE_URL` and `LLM_MODEL` are hardcoded in your `docker-compose.yml` so they are mathematically attested in the enclave's quote.
* **NEVER** hardcode `LLM_API_KEY`. It must be passed securely to the deployment using Dstack's Encrypted Secrets vault (`dstack secrets add`).

## 📚 Theoretical Foundations & Academic Inspiration

The architectural primitives of the Confidential Compliance Auditor (CCA) are heavily inspired by recent academic breakthroughs in mechanism design, game theory, and applied cryptography. Our platform translates several theoretical paradigms into practical, production-ready code.

### 1. Arrow's Information Paradox & The "Ironclad NDA"
The **Disclosure-Audit Paradox** our platform solves is a specific instance of **Arrow's Information Paradox** (Arrow, 1962). Historically, inventors and corporations have faced a "hold-up problem": to prove the compliance or value of their proprietary IP, they must disclose it to an auditor or buyer. However, once disclosed, the reviewer cannot "un-know" the information, creating a risk of expropriation. Traditional legal protections like standard NDAs rely on costly, imperfect *ex post* enforcement (litigation after a leak occurs). 

The CCA implements the concept of an **"Ironclad NDA"** via hardware cryptography. By shifting enforcement into a Trusted Execution Environment (TEE), we provide *ex interim* enforcement. The technology itself guarantees that the raw IP can only be evaluated against immutable compliance rules, perfectly eliminating the risk of human expropriation and the need for costly legal monitoring.

### 2. Conditional Recall and the "Pill X" Protocol
Our memory-wiping phase is directly inspired by the game-theoretic framework of **Conditional Recall** and the hypothetical **"Pill X."** Classical game theory assumes "perfect recall," meaning agents remember all past observations—a major barrier to sharing sensitive data. However, artificial agents are not bound by human cognitive constraints. 

By leveraging TEEs to act as "One-Time Programs" (OTPs), our architecture allows the AI auditor to ingest the IP, generate a compliance report, and then cryptographically and verifiably *forget* the underlying data. Our **Pill X Protocol** achieves this credible commitment to forgetting by explicitly zeroing out mutable bytearrays and forcing immediate garbage collection. This ensures that even if the TEE instance remains alive for subsequent requests, the context of the previous audit is mathematically annihilated.

### 3. Hardware-Enforced Confidential Inference
To execute this logic without exposing the data to cloud providers or host operating systems, the CCA utilizes **Confidential Inference** within Intel TDX enclaves. By using cryptographic Attestation Quotes, our platform allows the Auditee to remotely verify the enclave's integrity and the immutability of the AI's system prompt before deriving the shared ephemeral keys. This strictly aligns with modern research on deploying verifiable, multi-agent AI systems in high-stakes economic and legal settings.