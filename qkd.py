from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import numpy as np

def generate_qkd_key(length=256):
    # Step 1: Alice generates random bits and bases
    alice_bits = np.random.randint(2, size=length)         # 0 or 1 for each qubit
    alice_bases = np.random.choice(['Z', 'X'], size=length)  # Randomly choose Z or X basis for each qubit

    # Step 2: Bob randomly chooses his measurement bases
    bob_bases = np.random.choice(['Z', 'X'], size=length)    # Randomly choose Z or X basis for each qubit

    # Step 3: Create a quantum circuit with 'length' qubits and classical bits
    qc = QuantumCircuit(length, length)

    # Alice's preparation:
    # For each qubit, if Alice's chosen basis is X, apply a Hadamard gate.
    # Then, if her bit is 1, apply an X gate to encode the bit.
    for i in range(length):
        if alice_bases[i] == 'X':
            qc.h(i)
        if alice_bits[i] == 1:
            qc.x(i)

    # Bob's measurement:
    # Before measuring, if Bob's basis is X, apply a Hadamard gate.
    for i in range(length):
        if bob_bases[i] == 'X':
            qc.h(i)

    # Measure all qubits
    qc.measure(range(length), range(length))

    # Step 4: Set up the simulator.
    # Using the 'stabilizer' method is efficient for Clifford circuits and avoids coupling map constraints.
    simulator = AerSimulator(method="stabilizer")

    # Transpile the circuit without imposing any coupling map restrictions.
    transpiled_qc = transpile(qc, simulator, coupling_map=None)

    # Run the circuit with a single shot (we only need one measurement outcome).
    result = simulator.run(transpiled_qc, shots=1).result()

    # Extract the measurement outcome.
    counts = result.get_counts()
    if not counts:
        return None

    # The key in the counts dict is a bitstring; reverse it to match the qubit order.
    bob_bits = list(counts.keys())[0][::-1]

    # Step 5: Sift the key.
    # Only keep the bits where Alice's and Bob's bases matched.
    sifted_key = [int(bob_bits[i]) for i in range(length) if alice_bases[i] == bob_bases[i]]

    # Step 6: Convert the sifted key (a list of bits) into bytes.
    # For simplicity, group the bits into chunks of 8.
    num_bytes = len(sifted_key) // 8
    key_bytes = bytearray()
    for i in range(num_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | sifted_key[i * 8 + j]
        key_bytes.append(byte)

    # Convert the key to a readable string (binary and hex).
    bin_key = ''.join(str(bit) for bit in sifted_key)  # Binary string
    hex_key = key_bytes.hex()  # Hexadecimal string

    return bin_key, hex_key

# Example usage:
if __name__ == "__main__":
    bin_key, hex_key = generate_qkd_key()
    print("Generated key (binary):", bin_key)
    print("Generated key (hexadecimal):", hex_key)
