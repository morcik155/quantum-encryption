from flask import Flask, render_template
import socket
from aes_hmac import aes_gcm_decrypt, hmac_sha256

app = Flask(__name__)

# List to store messages
messages = []

@app.route('/')
def index():
    """Render the list of all received messages."""
    return render_template('index.html', messages=messages)

@app.route('/add_message/<message>')
def add_message(message):
    """Add a new message to the list (for testing purposes)."""
    messages.append(message)
    return 'Message added', 200

def server():
    while True:
        try:
            # Create server socket
            server_address = ('localhost', 65432)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(server_address)
                s.listen()
                print("Server is listening...")

                # Accept connection
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")

                    # Receive the shared key from the client
                    shared_key = conn.recv(32)  # Shared key size (256-bit key)

                    # Receive lengths of nonce, ciphertext, tag, and HMAC (4 bytes each)
                    length_nonce = int.from_bytes(conn.recv(4), 'big')
                    length_ciphertext = int.from_bytes(conn.recv(4), 'big')
                    length_tag = int.from_bytes(conn.recv(4), 'big')
                    length_hmac = int.from_bytes(conn.recv(4), 'big')

                    print(f"Server - Received lengths: Nonce={length_nonce}, Ciphertext={length_ciphertext}, Tag={length_tag}, HMAC={length_hmac}")

                    # Receive the actual data based on the received lengths
                    data = conn.recv(length_nonce + length_ciphertext + length_tag + length_hmac)

                    # Extract the nonce, ciphertext, tag, and HMAC
                    nonce = data[:length_nonce]
                    ciphertext = data[length_nonce:length_nonce + length_ciphertext]
                    tag = data[length_nonce + length_ciphertext:length_nonce + length_ciphertext + length_tag]
                    hmac = data[-length_hmac:]

                    # Print received details for debugging
                    print(f"Server - Received Nonce: {nonce}")
                    print(f"Server - Received Ciphertext: {ciphertext}")
                    print(f"Server - Received Tag: {tag}")
                    print(f"Server - Received HMAC: {hmac}")

                    # Decrypt the message with AES-GCM
                    decrypted_message = aes_gcm_decrypt(shared_key, nonce, ciphertext, tag)
                    if decrypted_message:
                        print(f"Decrypted message: {decrypted_message}")

                        # Verify the HMAC
                        if hmac_sha256(shared_key, decrypted_message) == hmac:
                            print("Message authentication succeeded")
                            messages.append(decrypted_message)
                        else:
                            print("HMAC verification failed, retrying connection...")
                            # Close the current connection and restart the server
                            conn.close()
                            break  # Will restart the server loop and wait for new connection
                    else:
                        print("Decryption failed, retrying connection...")
                        # Close the current connection and restart the server
                        conn.close()
                        break  # Will restart the server loop and wait for new connection

        except Exception as e:
            print(f"Error occurred: {e}. Restarting server...")
            break  # Exit the current server loop to restart it

if __name__ == "__main__":
    # Start the server in a separate thread to handle Flask and socket server simultaneously
    import threading
    threading.Thread(target=server).start()
    app.run(debug=True, use_reloader=False)  # Run Flask web application
