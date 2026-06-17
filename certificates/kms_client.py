import requests

KMS_URL = "http://localhost:8001"

def kms_generate_key():
    """
    Generates a new RSA key pair inside the KMS / vHSM.
    Returns (key_id, public_key_pem).
    """
    try:
        response = requests.post(f"{KMS_URL}/api/v1/keys/generate")
        response.raise_for_status()
        data = response.json()
        return data["key_id"], data["public_key_pem"]
    except Exception as e:
        raise ConnectionError(f"KMS サーバーでの鍵生成に失敗しました: {str(e)}")

def kms_sign(key_id, data_bytes):
    """
    Signs data bytes using the private key associated with key_id inside the KMS / vHSM.
    Returns signature bytes.
    """
    try:
        response = requests.post(f"{KMS_URL}/api/v1/keys/sign", json={
            "key_id": key_id,
            "data": data_bytes.hex()
        })
        response.raise_for_status()
        data = response.json()
        return bytes.fromhex(data["signature"])
    except Exception as e:
        raise ConnectionError(f"KMS サーバーでの署名処理に失敗しました: {str(e)}")

def kms_encrypt(plaintext):
    """
    Encrypts a string using the KMS transit engine.
    Returns (ciphertext_b64, nonce_b64).
    """
    try:
        response = requests.post(f"{KMS_URL}/api/v1/transit/encrypt", json={
            "plaintext": plaintext
        })
        response.raise_for_status()
        data = response.json()
        return data["ciphertext"], data["nonce"]
    except Exception as e:
        raise ConnectionError(f"KMS サーバーでのエンベロープ暗号化に失敗しました: {str(e)}")

def kms_decrypt(ciphertext, nonce):
    """
    Decrypts a ciphertext string using the KMS transit engine.
    Returns decrypted plaintext string.
    """
    try:
        response = requests.post(f"{KMS_URL}/api/v1/transit/decrypt", json={
            "ciphertext": ciphertext,
            "nonce": nonce
        })
        response.raise_for_status()
        data = response.json()
        return data["plaintext"]
    except Exception as e:
        raise ConnectionError(f"KMS サーバーでの復号処理に失敗しました: {str(e)}")
