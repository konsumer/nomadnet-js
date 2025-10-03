# this will decrypt output from create_message

import RNS
from RNS.vendor import umsgpack

# Your hex packet from JavaScript
packet_bytes = bytes.fromhex("0000072ec44973a8dee8e28d230fb4af8fe4001cdde87db9b2f6ccb6e73f3b30c1b0341925bc368f7f8601906a6f84b3b0372ece1c3a070676a02aebc851ed2094e24bbeddc173df33910ef88b30022b7acbe53b63a3aaad171eb6d5f639248a493d6cbef1e510ce5be7f519c1ad52d1905f2dd033e5e957adf4055723da9a37aa8f5ede174122737831ab4f8d4a907531ceb00a5e0a753f537cf12f63f45859befed6997d29b6123e8aa7e338bb30455c85ce2de2f39556bfd41de57907d102ab85c89af4a99ae09930ee8a46895576224c65c32af1c3d0b20469b3677ab4cf22e7c2bd5eae77eda37335f528e782f5629d2f")

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
