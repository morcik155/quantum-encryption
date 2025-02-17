import socket
from aes_hmac import aes_gcm_encrypt, hmac_sha256
from qkd import generate_qkd_key

def client():
    # Generate the QKD key (for AES encryption)
    bin_key, hex_key = generate_qkd_key()

    # Ensure the key is 32 bytes (256-bit) for AES-256
    shared_key = bytes.fromhex(hex_key)
    if len(shared_key) != 32:
        print(f"Key length is {len(shared_key)} bytes. Adjusting key length to 32 bytes.")

        # If the key is shorter or longer, we can pad or truncate it
        shared_key = shared_key.ljust(32, b'\0')[:32]  # Pad if shorter, truncate if longer
    # Connect to the server
    server_address = ('localhost', 65432)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)

        # Send the shared key to the server (it will use the same key)
        s.send(shared_key)

        # Encrypt a message with AES-256-GCM
        message = "Hello, this is a secure message!"
        nonce, ciphertext, tag = aes_gcm_encrypt(shared_key, message)

        # HMAC for authentication
        mac = hmac_sha256(shared_key, message)

        # Send the lengths of each part first: nonce, ciphertext, tag, and HMAC
        length_nonce = len(nonce)
        length_ciphertext = len(ciphertext)
        length_tag = len(tag)
        length_hmac = len(mac)

        # Send the lengths
        s.send(length_nonce.to_bytes(4, 'big'))  # Length of nonce (4 bytes for the length)
        s.send(length_ciphertext.to_bytes(4, 'big'))  # Length of ciphertext (4 bytes for the length)
        s.send(length_tag.to_bytes(4, 'big'))  # Length of tag (4 bytes for the length)
        s.send(length_hmac.to_bytes(4, 'big'))  # Length of HMAC (4 bytes for the length)

        # Send the actual data: nonce, ciphertext, tag, and HMAC
        s.send(nonce + ciphertext + tag + mac)

        print("Client - Sent data:", nonce + ciphertext + tag + mac)

if __name__ == "__main__":
    client()
