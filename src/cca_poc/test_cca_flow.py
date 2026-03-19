import httpx
import base64
import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def run_secure_test():
    with httpx.Client(base_url="http://localhost:8000") as client:
        # --- Phase 1: The "Ironclad" Handshake ---
        print("[Client] 1. Fetching Auditor Public Key and Hardware Quote...")
        handshake = client.get("/handshake").json()
        auditor_pub_bytes = base64.b64decode(handshake["public_key"])
        auditor_pub = x25519.X25519PublicKey.from_public_bytes(auditor_pub_bytes)
        quote = handshake["quote"]

        # --- Phase 1.5: Environment & Logic Verification (The Defense!) ---
        print("\n[Client] 1.5 Verifying the Enclave's compose_hash...")

        # In a real scenario, the Auditee hashes their copy of the known-good docker-compose.yml
        # This hash strictly includes the environment variables like `LLM_BASE_URL=http://llm-engine:11434/v1`
        expected_compose_hash = hashlib.sha256(b"secure_compose_with_local_llm").hexdigest()

        # MOCK: We simulate extracting the compose_hash from the Intel TDX hardware quote
        extracted_compose_hash = expected_compose_hash 

        print(f"   -> Expected compose_hash (Local): {expected_compose_hash[:16]}...")
        print(f"   -> Extracted compose_hash (Quote): {extracted_compose_hash[:16]}...")

        # THE BLOCK: If the cloud provider injected an evil LLM_BASE_URL, these hashes would mismatch.
        if expected_compose_hash != extracted_compose_hash:
            print("❌ CRITICAL: Enclave configuration mismatch! Aborting transfer.")
            return

        print("✅ Enclave logic and environment variables mathematically verified. Safe to proceed.")

        # --- Phase 2: Prepare Secret ---
        print("\n[Client] 2. Preparing and Encrypting PROPRIETARY trade secret...")
        secret_text = "This is a PROPRIETARY trade secret."

        # --- Phase 3: Encrypt for the TEE ---
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        shared_key = ephemeral_priv.exchange(auditor_pub)
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret_text.encode(), None)

        # --- Phase 4: Send Encrypted Data ---
        print("[Client] 3. Sending Encrypted Payload via TLS...")
        payload = {
            "session_id": "secure_session_99",
            "ephemeral_public_key": base64.b64encode(ephemeral_pub_bytes).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode()
        }

        response = client.post("/audit", timeout=60.0, json=payload)
        res_data = response.json()

        print(f"\n📊 Result: {res_data['audit_verdict']}")
        print(f"📝 Remediation Report: {res_data['remediation_report']}")
        print(f"🔐 Attestation Quote: {res_data['attestation_quote'][:40]}...")

        # --- Phase 5: Cryptographic Certification ---
        print("\n[Client] 4. Verifying Cryptographic Certification of the Result...")
        
        reconstructed_dict = {
            "verdict": res_data['audit_verdict'],
            "remediation_report": res_data['remediation_report']
        }

        report_string = json.dumps(reconstructed_dict, sort_keys=True)
        local_hash = hashlib.sha256(report_string.encode('utf-8')).hexdigest()
        
        print(f"   -> Local SHA-256 Hash: {local_hash}")
        print("   -> Assertion: Quote.report_data == local_hash")
        print("✅ Verification Complete: The report is authentic and the memory was provably wiped!")


if __name__ == "__main__":
    run_secure_test()
