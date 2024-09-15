# Hex data as a string (replace this with your actual hex data)
hex_data = "HEX STRING HERE"

# Convert hex string to bytes
byte_data = bytes.fromhex(hex_data)

# Function to XOR the data with a given key
def xor_with_key(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Brute-force multi-byte XOR keys of length 1 to 8
key_lengths = range(1, 9)  # Try key lengths from 1 to 8
for length in key_lengths:
    # Generate all possible keys of the given length (brute force)
    for key in range(256 ** length):
        # Convert the key into a byte sequence
        key_bytes = key.to_bytes(length, 'big')
        decrypted_data = xor_with_key(byte_data, key_bytes)
        try:
            ascii_output = decrypted_data.decode('ascii', errors='ignore')
            if any(char.isprintable() for char in ascii_output):  # Check for readable output
                print(f"Key (Length {length}): {key_bytes} - ASCII Output: {ascii_output}")
        except Exception as e:
            continue
