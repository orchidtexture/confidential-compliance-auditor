import base64
import os
import json
import hashlib
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --- 1. Define the Mock Behaviors ---

class MockDstackClient:

    def get_key(self, path, purpose):
        mock_key = MagicMock()
        mock_key.key = "00" * 32
        return mock_key


    def get_quote(self, report_data):
        mock_quote = MagicMock()
        mock_quote.quote = f"mock_quote_for_{report_data}"
        return mock_quote


    def info(self):
        mock_info = MagicMock()
        mock_info.app_id = "simulator_app_id"
        return mock_info


class MockOpenAIClient:
    """Mocks the official OpenAI Python SDK for our local test suite."""
    
    def __init__(self, *args, **kwargs):
        self.chat = MagicMock()
        # Bind the create method to our dynamic response generator
        self.chat.completions.create.side_effect = self._mock_create


    def _mock_create(self, *args, **kwargs):
        messages = kwargs.get('messages', [])
        
        # Safely extract the user's decrypted secret from the prompt
        user_content = ""
        for msg in messages:
            if msg.get("role") == "user":
                user_content = msg.get("content", "").lower()
                break
        
        # Simulate the LLM's adherence to the Immutable System Prompt
        if "proprietary" in user_content:
            json_str = json.dumps({
                "verdict": "NON-COMPLIANT", 
                "remediation_report": "Proprietary business logic or trade secrets were detected."
            })
        else:
            json_str = json.dumps({
                "verdict": "COMPLIANT", 
                "remediation_report": "No issues found."
            })
        
        # PROPERLY construct the deeply nested object structure the OpenAI SDK returns
        mock_message = MagicMock()
        mock_message.content = json_str
        
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        
        mock_response = MagicMock()
        mock_response.choices = [mock_choice] # Explicitly a list so [0] works!
        
        return mock_response

# --- 2. Patch GLOBALLY BEFORE importing the app ---
# By using .start(), the patch remains permanently active for all tests in this file!
patch('dstack_sdk.DstackClient', new=MockDstackClient).start()
patch('openai.OpenAI', new=MockOpenAIClient).start()

from src.cca_poc.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


# --- Helper: Client-side Encryption ---
def encrypt_for_tee(plaintext: str, auditor_pub_b64: str):
    auditor_pub_bytes = base64.b64decode(auditor_pub_b64)
    auditor_pub = x25519.X25519PublicKey.from_public_bytes(auditor_pub_bytes)

    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    shared_key = ephemeral_priv.exchange(auditor_pub)
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "ephemeral_public_key": base64.b64encode(ephemeral_pub_bytes).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }


# --- Test Cases ---

def test_handshake():
    """Test Phase 1: Identity and Key Release."""
    response = client.get("/handshake")
    assert response.status_code == 200
    data = response.json()
    assert "public_key" in data
    assert "quote" in data
    assert "mock_quote_for_" in data["quote"]


def test_audit_non_compliant_scenario():
    """Test Phase 3: Analysis detects proprietary data and redacts the report."""
    handshake = client.get("/handshake").json()

    # Encrypt data WITH the violation keyword
    payload = encrypt_for_tee("This contains proprietary algorithms", handshake["public_key"])
    payload["session_id"] = "test_session_non_compliant"

    response = client.post("/audit", json=payload)
    data = response.json()

    print("data:", data)  # Debug print to inspect the response structure
    
    assert response.status_code == 200
    assert data["audit_verdict"] == "NON-COMPLIANT"
    assert "remediation_report" in data
    assert len(data["remediation_report"]) > 0


def test_audit_compliant_scenario():
    """Test Phase 3: Analysis passes safe data."""
    handshake = client.get("/handshake").json()

    # Encrypt data WITHOUT the keyword
    payload = encrypt_for_tee("This is standard open source logic.", handshake["public_key"])
    payload["session_id"] = "test_session_compliant"

    response = client.post("/audit", json=payload)
    data = response.json()
    
    assert response.status_code == 200
    assert data["audit_verdict"] == "COMPLIANT"
    assert data["remediation_report"] == "No issues found."


def test_decryption_failure():
    """Test Phase 2: Ensure the TEE rejects tampered or incorrectly encrypted data."""
    bad_payload = {
        "session_id": "bad_session",
        "ephemeral_public_key": base64.b64encode(b"0"*32).decode(),
        "ciphertext": base64.b64encode(b"garbage").decode(),
        "nonce": base64.b64encode(os.urandom(12)).decode()
    }

    response = client.post("/audit", json=bad_payload)
    assert response.status_code == 400
    assert "Decryption failed" in response.json()["detail"]


def test_cryptographic_certification():
    """Test Phase 5: Ensure the client can mathematically verify the signed JSON report."""
    handshake = client.get("/handshake").json()
    payload = encrypt_for_tee("Safe data here", handshake["public_key"])
    payload["session_id"] = "cert_test_session"

    response = client.post("/audit", json=payload)
    res_data = response.json()
    
    # 1. Reconstruct the dictionary that the server supposedly hashed
    reconstructed_dict = {
        "verdict": res_data["audit_verdict"],
        "remediation_report": res_data["remediation_report"]
    }
    
    # 2. Hash it deterministically
    report_string = json.dumps(reconstructed_dict, sort_keys=True)
    expected_hash = hashlib.sha256(report_string.encode('utf-8')).hexdigest()
    
    # 3. Assert the hardware quote contains our exact hash
    expected_quote = f"mock_quote_for_{expected_hash}"
    assert res_data["attestation_quote"] == expected_quote, "Cryptographic signature mismatch!"


def test_stateless_immutability():
    """
    Validates that the server is stateless and replay attacks yield no new IP.
    """
    handshake = client.get("/handshake").json()
    payload = encrypt_for_tee("Proprietary trade secret data", handshake["public_key"])
    payload["session_id"] = "stateless_session"

    # Run 1
    resp1 = client.post("/audit", json=payload)
    assert resp1.status_code == 200
    quote1 = resp1.json()["attestation_quote"]

    # Run 2 (Replay)
    resp2 = client.post("/audit", json=payload)
    assert resp2.status_code == 200
    quote2 = resp2.json()["attestation_quote"]

    # The hardware quotes must match exactly, proving no state was leaked or altered
    assert quote1 == quote2
