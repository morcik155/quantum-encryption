from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

def aes_gcm_encrypt(key, data):
    """Encrypt data using AES-GCM mode."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    nonce = cipher.nonce  # Nonce (or IV)
    return nonce, ciphertext, tag

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    """Decrypt data using AES-GCM mode and verify the tag."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode()  # Return decoded plaintext
    except ValueError:
        raise ValueError("Decryption failed or tag mismatch!")

def hmac_sha256(key, message):
    """Generate HMAC using SHA256."""
    hmac = HMAC.new(key, msg=message.encode(), digestmod=SHA256)
    return hmac.digest()
