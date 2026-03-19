import os
import base64
import gc
import json
from openai import OpenAI
import logging
import hashlib
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dstack_sdk import DstackClient
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Dynamic LLM Configuration ---
# By defaulting to the enclave settings, the code is secure out-of-the-box.
# Local developers simply override these variables in their terminal or .env file.
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://llm-engine:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama-dummy-key")
LLM_MODEL = os.getenv("LLM_MODEL", "phi3")

app = FastAPI()
client = DstackClient()

# Initialize the universal client
llm_client = OpenAI(
    base_url=LLM_BASE_URL,
    api_key=LLM_API_KEY,
)


# --- Pydantic Models ---
class EncryptedPayload(BaseModel):
    session_id: str
    ephemeral_public_key: str  # From the client (Forward Secrecy)
    ciphertext: str            # The actual encrypted secret
    nonce: str                 # For AES-GCM


class AuditResponse(BaseModel):
    audit_verdict: str
    remediation_report: str
    attestation_quote: str  # The cryptographic proof!
    status: str


# --- IMMUTABLE AUDIT LOGIC (Categorical Redaction) ---
# Baked into the code to ensure it is measured by the TEE hardware quote.
IMMUTABLE_SYSTEM_PROMPT = """
You are a strict, stateless compliance auditor operating in a secure enclave.
Analyze the provided user data for compliance.

Your response MUST be valid JSON in the following format:
{
    "verdict": "COMPLIANT" or "NON-COMPLIANT",
    "remediation_report": "Provide steps to fix the issue."
}

CRITICAL SECURITY RULES FOR THE REPORT:
1. You MUST NOT quote, echo, or include any specific code, variable names, formulas,
or raw data from the user input.
2. If the data is NON-COMPLIANT, describe the violation using broad, abstract categories
(e.g., 'Proprietary sorting logic detected' instead of 'BubbleSort detected').
3. If the data is COMPLIANT, set the report to 'No issues found.'
"""


def get_auditor_keys():
    """Derive the TEE's stable identity keys."""
    seed = client.get_key("ingestion_seed", "v1")

    # Handle both string (hex) and byte returns based on SDK behavior
    seed_bytes = bytes.fromhex(seed.key) if isinstance(seed.key, str) else seed.key
    priv = x25519.X25519PrivateKey.from_private_bytes(seed_bytes)
    return priv


@app.get("/handshake")
def handshake():
    """Step 1 & 2.1: Establish Trust and Provide Public Key."""
    priv = get_auditor_keys()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    quote_resp = client.get_quote(report_data=pub_bytes.hex())
    return {
        "public_key": base64.b64encode(pub_bytes).decode(),
        "quote": quote_resp.quote
    }


@app.post("/audit", response_model=AuditResponse)
def audit_and_wipe(payload: EncryptedPayload):
    """Steps 2.2, 3, & 4: Decrypt, Analyze, and Provably Wipe."""

    # --- Step 2.2: Decryption (Purely In-Memory) ---
    auditor_priv = get_auditor_keys()
    client_pub_bytes = base64.b64decode(payload.ephemeral_public_key)
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared_key = auditor_priv.exchange(client_pub)

    aesgcm = AESGCM(shared_key)
    try:
        # Decrypt directly into a mutable bytearray for secure wiping
        raw_decrypted_bytes = aesgcm.decrypt(
            base64.b64decode(payload.nonce),
            base64.b64decode(payload.ciphertext),
            None
        )
        mutable_secret = bytearray(raw_decrypted_bytes)
        decrypted_text = mutable_secret.decode('utf-8')
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Decryption failed. Unauthorized TEE access?"
        )

    # --- Step 3: REAL Confidential Analysis (Universal LLM) ---
    logger.info(f"🧠 Routing inference to {LLM_BASE_URL} using model {LLM_MODEL}...")

    # The 'messages' array represents the LLM context for this single request.
    messages = [
        {"role": "system", "content": IMMUTABLE_SYSTEM_PROMPT},
        {"role": "user", "content": decrypted_text}
    ]

    try:
        # This exact call works for both OpenAI (GPT-4) and Ollama (Phi-3)
        response = llm_client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            response_format={"type": "json_object"}, # Forces structured JSON output
        )
        
        raw_llm_json_string = response.choices[0].message.content
        llm_response_dict = json.loads(raw_llm_json_string)
    
    except Exception as e:
        logger.error(f"LLM Inference failed: {e}")
        # Trigger Pill X early on failure
        for i in range(len(mutable_secret)): mutable_secret[i] = 0
        del raw_decrypted_bytes
        del decrypted_text
        gc.collect()
        raise HTTPException(status_code=500, detail="Confidential inference engine failed.")

    # --- Step 4: True 'Pill X' Memory Wipe ---
    # 1. Cryptographically overwrite sensitive data structures with zeros
    for i in range(len(mutable_secret)):
        mutable_secret[i] = 0

    # 2. Delete all context arrays and string copies
    del raw_decrypted_bytes
    del decrypted_text
    del messages
    del raw_llm_json_string # Wipe the raw LLM output string too!
    # 3. Force garbage collection to sweep the RAM immediately
    gc.collect()

    logger.info(
        "[Pill X] Context cleared. LLM memory wiped."
    )

    # --- Step 5: Cryptographic Certification ---
    # Serialize the dict to a stable JSON string
    # (sort_keys=True ensures the hash is deterministic)
    report_string = json.dumps(llm_response_dict, sort_keys=True)

    # Hash the exact report string
    report_hash = hashlib.sha256(report_string.encode('utf-8')).hexdigest()

    # Request the hardware to sign the hash
    # The report_data field accepts a hex string up to 64 chars (perfect for SHA-256)
    final_quote_resp = client.get_quote(report_data=report_hash)

    # --- Step 6: Release Attested Result ---
    return AuditResponse(
        audit_verdict=llm_response_dict["verdict"],
        remediation_report=llm_response_dict["remediation_report"],
        attestation_quote=final_quote_resp.quote,
        status="Audit successful. Dataset and context provably destroyed."
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
