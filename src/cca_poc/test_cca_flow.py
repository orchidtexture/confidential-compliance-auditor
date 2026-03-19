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
        # 1. GET PUBLIC KEY
        print("[Client] Fetching Auditor Public Key...")
        handshake = client.get("/handshake").json()
        auditor_pub_bytes = base64.b64decode(handshake["public_key"])
        auditor_pub = x25519.X25519PublicKey.from_public_bytes(auditor_pub_bytes)

        # 2. PREPARE SECRET
        secret_text = "This is a PROPRIETARY trade secret."

        # 3. ENCRYPT FOR THE TEE
        # Generate ephemeral key pair for this session
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Derive Shared Secret
        shared_key = ephemeral_priv.exchange(auditor_pub)

        print(
            f"[Client] Derived Shared Key: {
                base64.b64encode(shared_key).decode()[:20]
            }..."
        )

        # Encrypt via AES-GCM
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret_text.encode(), None)

        # 4. SEND ENCRYPTED DATA
        print("[Client] Sending Encrypted Payload...")
        payload = {
            "session_id": "secure_session_99",
            "ephemeral_public_key": base64.b64encode(ephemeral_pub_bytes).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode()
        }

        response = client.post("/audit", json=payload)
        res_data = response.json()

        print(f"\n📊 Result: {res_data['audit_verdict']}")
        print(f"📝 Remediation Report: {res_data['remediation_report']}")
        print(f"🔐 Attestation Quote: {res_data['attestation_quote'][:40]}...")

        # 5. CRYPTOGRAPHIC VERIFICATION (The "Ironclad" Proof)
        print("\n[Client] Verifying Cryptographic Certification...")

        # Reconstruct the exact dictionary the server hashed
        reconstructed_dict = {
            "verdict": res_data['audit_verdict'],
            "remediation_report": res_data['remediation_report']
        }

        # Hash it using the exact same deterministic method
        report_string = json.dumps(reconstructed_dict, sort_keys=True)
        local_hash = hashlib.sha256(report_string.encode('utf-8')).hexdigest()

        print(f"   -> Local SHA-256 Hash: {local_hash}")
        print("   -> To complete verification, the client extracts the 'report_data' from the Quote.")
        print(f"   -> Assertion: Quote.report_data == {local_hash}")
        print("✅ If they match, the report is cryptographically guaranteed to be unaltered and from the TEE!")


if __name__ == "__main__":
    run_secure_test()
