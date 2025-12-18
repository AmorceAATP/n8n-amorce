"""
CrewAI Agent HTTP Server for Integration Testing

Exposes a CrewAI SecureAgent as an HTTP endpoint that can receive
signed Amorce transactions from n8n or other agents.

Usage:
    python crewai_http_server.py

The server listens on http://localhost:8765/agent
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import hashlib

# Generate EC key pair for this agent
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Export public key as PEM for registration
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

AGENT_ID = "crewai-henri-seller"


def sign_response(data: dict) -> str:
    """Sign response data with agent's private key."""
    payload = json.dumps(data, sort_keys=True)
    signature = private_key.sign(
        payload.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(payload: str, signature: str, sender_public_key_pem: str) -> bool:
    """Verify incoming signature from sender."""
    try:
        sender_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode(),
            backend=default_backend()
        )
        signature_bytes = base64.b64decode(signature)
        sender_key.verify(signature_bytes, payload.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


class CrewAIHandler(BaseHTTPRequestHandler):
    """HTTP handler for CrewAI agent requests."""
    
    def do_GET(self):
        """Health check endpoint."""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'healthy',
                'agent_id': AGENT_ID,
                'type': 'crewai-secure-agent'
            }).encode())
        elif self.path == '/info':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'agent_id': AGENT_ID,
                'public_key': public_key_pem,
                'capabilities': ['counter_offer', 'generate_receipt', 'check_inventory']
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle incoming signed transactions."""
        if self.path != '/agent':
            self.send_response(404)
            self.end_headers()
            return
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return
        
        # Extract transaction fields
        consumer_id = request.get('consumer_id')
        provider_id = request.get('provider_id')
        timestamp = request.get('timestamp')
        signature = request.get('signature')
        request_body = request.get('body', {})
        
        print(f"\n{'='*50}")
        print(f"📨 Received transaction from: {consumer_id}")
        print(f"   Provider: {provider_id}")
        print(f"   Timestamp: {timestamp}")
        print(f"   Signature present: {bool(signature)}")
        print(f"   Request: {request_body}")
        
        # Verify signature (in production, would lookup consumer's public key from Trust Directory)
        if signature:
            print(f"   ✅ Signature received (would verify via Trust Directory)")
        else:
            print(f"   ⚠️ No signature - request not authenticated")
        
        # Process the request based on intent
        intent = request_body.get('intent', 'unknown')
        
        if intent == 'counter_offer':
            # Henri makes a counter offer
            original_price = request_body.get('price', 0)
            counter_price = int(original_price * 1.1)  # 10% markup
            
            response_data = {
                'status': 'counter_offer',
                'original_price': original_price,
                'counter_price': counter_price,
                'reasoning': 'Fair market value based on condition and demand',
                'from_agent': AGENT_ID
            }
            
        elif intent == 'check_inventory':
            product = request_body.get('product', 'unknown')
            response_data = {
                'status': 'available',
                'product': product,
                'condition': 'Excellent',
                'quantity': 1,
                'from_agent': AGENT_ID
            }
            
        elif intent == 'generate_receipt':
            response_data = {
                'status': 'receipt_generated',
                'receipt_id': f"RCP-{hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()}",
                'seller': AGENT_ID,
                'verified_by_amorce': True,
                'from_agent': AGENT_ID
            }
            
        else:
            # Echo request for testing
            response_data = {
                'status': 'received',
                'echo': request_body,
                'message': f'Hello from {AGENT_ID}! I received your request.',
                'from_agent': AGENT_ID
            }
        
        # Sign the response
        response_signature = sign_response(response_data)
        
        final_response = {
            'provider_id': AGENT_ID,
            'consumer_id': consumer_id,
            'data': response_data,
            'signature': response_signature
        }
        
        print(f"   📤 Response: {response_data.get('status')}")
        print(f"   🔐 Signed response")
        print(f"{'='*50}\n")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(final_response).encode())
    
    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[CrewAI] {args[0]}")


def main():
    port = 8765
    server = HTTPServer(('localhost', port), CrewAIHandler)
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║       CrewAI Agent HTTP Server (Amorce-enabled)          ║
╠══════════════════════════════════════════════════════════╣
║  Agent ID:    {AGENT_ID:<40}  ║
║  Endpoint:    http://localhost:{port}/agent               ║
║  Health:      http://localhost:{port}/health              ║
║  Info:        http://localhost:{port}/info                ║
╠══════════════════════════════════════════════════════════╣
║  Capabilities:                                           ║
║    • counter_offer - Make counter offers on products     ║
║    • check_inventory - Check product availability        ║
║    • generate_receipt - Generate signed receipts         ║
╠══════════════════════════════════════════════════════════╣
║  Press Ctrl+C to stop                                    ║
╚══════════════════════════════════════════════════════════╝
""")
    
    print(f"Public Key:\n{public_key_pem}\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
