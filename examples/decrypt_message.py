# this will decrypt output from create_message

import RNS
from RNS.vendor import umsgpack

# Your hex packet from JavaScript
packet_bytes = bytes.fromhex("0000072ec44973a8dee8e28d230fb4af8fe400ae40d61412277da5c1e23fd35ae49f4ed845992507c571dc487168d20b43d03e270aa0e916b8ae319523814957bc087909756512a119a74c03571329cbf2ea927bae25e7f66fc2c9d5e1549bc81a1c35b2eb5700d6e8f0c481e7d7379e8408d7ce569be351f64b2c480424404b85bb25d67f1a205f583d28d64b280c0fb431e6cfa2770a6320f45f4d777220801d1b34969ee4abd9697f7fb448e391321b23211e614b2a58e286c574970c13ad456c8db2e9b886a895bb602c4fe6561137db38761f013b73a64074263fa10a708bd07d5553d615d959c2f565bed92bd609eece")

# Parse packet (assuming you have a parse function)
# Or manually:
destination_hash = packet_bytes[2:18]
data = packet_bytes[19:]

print(f"Destination: {destination_hash.hex()}")
print(f"Data length: {len(data)}")

# Load identity for Client A
identity_a = RNS.Identity.from_bytes(bytes.fromhex('205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313'))

# Ratchets
ratchets = [
    bytes.fromhex('205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066'),
    bytes.fromhex('28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45')
]

# Decrypt
try:
    decrypted = identity_a.decrypt(data, ratchets=ratchets)
    print(f"Decryption successful! Length: {len(decrypted)}")
    
    # Skip 80 byte header and unpack
    message_data = umsgpack.unpackb(decrypted[80:])
    timestamp, title, content, fields = message_data
    print(f"Timestamp: {timestamp}")
    print(f"Title: {title}")
    print(f"Content: {content.decode()}")
    print(f"Fields: {fields}")
except Exception as e:
    print(f"Decryption failed: {e}")
