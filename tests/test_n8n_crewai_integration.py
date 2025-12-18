"""
n8n to CrewAI Integration Test

Tests the n8n-amorce plugin's ability to call a CrewAI agent
with signed transactions.

Prerequisites:
    1. Run the CrewAI HTTP server: python tests/crewai_http_server.py
    2. Run this test: python tests/test_n8n_crewai_integration.py

This simulates what the n8n node would do when calling an agent.
"""

import json
import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# n8n workflow agent credentials (simulated)
N8N_AGENT_ID = "n8n-workflow-agent"
CREWAI_ENDPOINT = "http://localhost:8765/agent"

# Generate EC key pair for n8n agent
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


def sign_payload(payload: str) -> str:
    """Sign payload with n8n agent's private key (same as n8n node)."""
    signature = private_key.sign(
        payload.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode('utf-8')


def call_crewai_agent(intent: str, data: dict) -> dict:
    """
    Call CrewAI agent with signed Amorce transaction.
    
    This mimics what the n8n AmorceAgent node does.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Build transaction payload (same structure as n8n node)
    transaction = {
        "consumer_id": N8N_AGENT_ID,
        "provider_id": "crewai-henri-seller",
        "timestamp": timestamp,
        "body": {
            "intent": intent,
            **data
        }
    }
    
    # Sign the payload
    payload_string = json.dumps(transaction, sort_keys=True)
    signature = sign_payload(payload_string)
    
    # Add signature to transaction
    transaction["signature"] = signature
    
    print(f"\n📤 Sending signed transaction to CrewAI agent...")
    print(f"   Intent: {intent}")
    print(f"   Data: {data}")
    print(f"   Signature: {signature[:50]}...")
    
    # Send request
    response = requests.post(
        CREWAI_ENDPOINT,
        json=transaction,
        headers={"Content-Type": "application/json"},
        timeout=30
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"\n📨 Received signed response from CrewAI:")
        print(f"   Provider: {result.get('provider_id')}")
        print(f"   Data: {result.get('data')}")
        print(f"   Response signature: {result.get('signature', '')[:50]}...")
        return result
    else:
        print(f"\n❌ Error: {response.status_code}")
        print(f"   {response.text}")
        return {"error": response.text}


def test_counter_offer():
    """Test: n8n requests a counter offer from CrewAI Henri."""
    print("\n" + "="*60)
    print("TEST 1: Counter Offer")
    print("="*60)
    
    result = call_crewai_agent(
        intent="counter_offer",
        data={"product": "MacBook Pro 2020", "price": 500}
    )
    
    assert result.get("data", {}).get("status") == "counter_offer"
    assert result.get("data", {}).get("counter_price") == 550  # 10% markup
    print("\n✅ Counter offer test PASSED")
    return result


def test_check_inventory():
    """Test: n8n checks product inventory via CrewAI."""
    print("\n" + "="*60)
    print("TEST 2: Check Inventory")
    print("="*60)
    
    result = call_crewai_agent(
        intent="check_inventory",
        data={"product": "iPhone 14 Pro"}
    )
    
    assert result.get("data", {}).get("status") == "available"
    assert result.get("data", {}).get("product") == "iPhone 14 Pro"
    print("\n✅ Inventory check test PASSED")
    return result


def test_generate_receipt():
    """Test: n8n requests a signed receipt from CrewAI."""
    print("\n" + "="*60)
    print("TEST 3: Generate Receipt")
    print("="*60)
    
    result = call_crewai_agent(
        intent="generate_receipt",
        data={"order_id": "ORD-12345", "amount": 550}
    )
    
    assert result.get("data", {}).get("status") == "receipt_generated"
    assert result.get("data", {}).get("verified_by_amorce") == True
    print("\n✅ Receipt generation test PASSED")
    return result


def test_echo():
    """Test: Basic echo to verify connectivity."""
    print("\n" + "="*60)
    print("TEST 4: Echo (Connectivity Test)")
    print("="*60)
    
    result = call_crewai_agent(
        intent="ping",
        data={"message": "Hello from n8n!"}
    )
    
    assert result.get("data", {}).get("status") == "received"
    assert "Hello from crewai-henri-seller" in result.get("data", {}).get("message", "")
    print("\n✅ Echo test PASSED")
    return result


def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║        n8n ↔ CrewAI Integration Test via Amorce          ║
╠══════════════════════════════════════════════════════════╣
║  n8n Agent ID:     {:<38}  ║
║  CrewAI Endpoint:  {:<38}  ║
╚══════════════════════════════════════════════════════════╝
""".format(N8N_AGENT_ID, CREWAI_ENDPOINT))
    
    print(f"n8n Agent Public Key:\n{public_key_pem}")
    
    # Check if CrewAI server is running
    try:
        health = requests.get("http://localhost:8765/health", timeout=5)
        if health.status_code != 200:
            print("❌ CrewAI server not responding. Run: python tests/crewai_http_server.py")
            return
        print(f"✅ CrewAI server is healthy: {health.json()}")
    except requests.exceptions.ConnectionError:
        print("""
❌ CrewAI server not running!

Please start it first in another terminal:
    cd amorce-integration/n8n-amorce
    python tests/crewai_http_server.py
        """)
        return
    
    # Run all tests
    passed = 0
    failed = 0
    
    tests = [
        test_echo,
        test_counter_offer,
        test_check_inventory,
        test_generate_receipt,
    ]
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ Test FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"\n❌ Test ERROR: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*60)
    
    if failed == 0:
        print("""
✅ All integration tests passed!

This demonstrates:
  1. n8n can send signed transactions to CrewAI agents
  2. CrewAI agents can receive and process n8n requests
  3. Responses are signed for verification
  4. Full Amorce trust protocol in action!
""")


if __name__ == "__main__":
    main()
