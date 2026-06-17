import os
import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 8001
STORE_DIR = os.path.join(os.path.dirname(__file__), "secure_store")
MASTER_KEY_FILE = os.path.join(os.path.dirname(__file__), "master.key")

# Ensure directory structures
os.makedirs(STORE_DIR, exist_ok=True)

# Generate or load Master Key
if not os.path.exists(MASTER_KEY_FILE):
    master_key = AESGCM.generate_key(bit_length=256)
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(master_key)
else:
    with open(MASTER_KEY_FILE, "rb") as f:
        master_key = f.read()

aesgcm = AESGCM(master_key)

class KMSRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress request logging to keep console clean
        pass
        
    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            params = json.loads(body) if body else {}
        except ValueError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        if self.path == "/api/v1/keys/generate":
            # Generate key inside vHSM
            try:
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Serialize private key
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Serialize public key
                public_pem = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                # Generate unique key identifier
                import uuid
                key_id = str(uuid.uuid4())
                
                # Encrypt private key using Master Key before saving to store
                nonce = os.urandom(12)
                encrypted_private = aesgcm.encrypt(nonce, private_pem, None)
                
                # Save to secure store
                store_data = {
                    "encrypted_key": base64.b64encode(encrypted_private).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8')
                }
                
                with open(os.path.join(STORE_DIR, f"{key_id}.json"), "w") as f:
                    json.dump(store_data, f)
                    
                self._send_json(200, {
                    "key_id": key_id,
                    "public_key_pem": public_pem
                })
            except Exception as e:
                self._send_json(500, {"error": f"Failed to generate key: {str(e)}"})

        elif self.path == "/api/v1/keys/sign":
            key_id = params.get("key_id")
            data_hex = params.get("data")
            
            if not key_id or not data_hex:
                self._send_json(400, {"error": "Missing key_id or data"})
                return
                
            key_path = os.path.join(STORE_DIR, f"{key_id}.json")
            if not os.path.exists(key_path):
                self._send_json(404, {"error": "Key not found"})
                return
                
            try:
                # Load encrypted private key from store
                with open(key_path, "r") as f:
                    store_data = json.load(f)
                    
                encrypted_private = base64.b64decode(store_data["encrypted_key"])
                nonce = base64.b64decode(store_data["nonce"])
                
                # Decrypt private key into volatile memory for signing
                private_pem = aesgcm.decrypt(nonce, encrypted_private, None)
                private_key = serialization.load_pem_private_key(private_pem, password=None)
                
                # Sign data
                data_bytes = bytes.fromhex(data_hex)
                signature = private_key.sign(
                    data_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
                self._send_json(200, {
                    "signature": signature.hex()
                })
            except Exception as e:
                self._send_json(500, {"error": f"Signing failed: {str(e)}"})

        elif self.path == "/api/v1/transit/encrypt":
            plaintext = params.get("plaintext")
            if not plaintext:
                self._send_json(400, {"error": "Missing plaintext"})
                return
                
            try:
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
                
                self._send_json(200, {
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8')
                })
            except Exception as e:
                self._send_json(500, {"error": f"Encryption failed: {str(e)}"})

        elif self.path == "/api/v1/transit/decrypt":
            ciphertext_b64 = params.get("ciphertext")
            nonce_b64 = params.get("nonce")
            
            if not ciphertext_b64 or not nonce_b64:
                self._send_json(400, {"error": "Missing ciphertext or nonce"})
                return
                
            try:
                ciphertext = base64.b64decode(ciphertext_b64)
                nonce = base64.b64decode(nonce_b64)
                
                plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                self._send_json(200, {
                    "plaintext": plaintext_bytes.decode('utf-8')
                })
            except Exception as e:
                self._send_json(500, {"error": f"Decryption failed: {str(e)}"})
        else:
            self._send_json(404, {"error": "Endpoint not found"})

def run_server():
    server = HTTPServer(("localhost", PORT), KMSRequestHandler)
    print(f"vHSM KMS Server running on http://localhost:{PORT}")
    server.serve_forever()

if __name__ == "__main__":
    run_server()
