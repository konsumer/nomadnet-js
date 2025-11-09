#!/usr/bin/env python3
import hashlib


def get_message_id_original(packetBytes: bytes) -> bytes:
    """Original implementation - doesn't handle header_type=1 specially"""
    hashable_part = bytes([packetBytes[0] & 0b00001111])
    hashable_part += packetBytes[2:]
    return hashlib.sha256(hashable_part).digest()


def get_message_id_skip_transport_id(packetBytes: bytes) -> bytes:
    """Skip transport_id when header_type=1"""
    header_type = (packetBytes[0] >> 6) & 0b11
    hashable_part = bytes([packetBytes[0] & 0b00001111])

    if header_type == 1:
        # Skip header + hops + transport_id (2 + 16 = 18 bytes)
        hashable_part += packetBytes[18:]
    else:
        # Skip header + hops (2 bytes)
        hashable_part += packetBytes[2:]

    return hashlib.sha256(hashable_part).digest()


def get_message_id_reorder_transport_id(packetBytes: bytes) -> bytes:
    """Put transport_id after destination for hashing when header_type=1"""
    header_type = (packetBytes[0] >> 6) & 0b11
    hashable_part = bytes([packetBytes[0] & 0b00001111])

    if header_type == 1:
        # For header_type=1: skip header+hops, then destination_hash, then transport_id, then rest
        hashable_part += packetBytes[18:34]  # destination_hash
        hashable_part += packetBytes[2:18]  # transport_id
        hashable_part += packetBytes[34:]  # rest of data
    else:
        hashable_part += packetBytes[2:]

    return hashlib.sha256(hashable_part).digest()


def get_message_id_exclude_hops(packetBytes: bytes) -> bytes:
    """Always exclude hops byte from hash"""
    header_type = (packetBytes[0] >> 6) & 0b11
    hashable_part = bytes([packetBytes[0] & 0b00001111])

    if header_type == 1:
        # Include transport_id but not hops
        hashable_part += packetBytes[2:]  # Everything after hops
    else:
        # Skip hops
        hashable_part += packetBytes[2:]

    return hashlib.sha256(hashable_part).digest()


def get_message_id_special_ordering(packetBytes: bytes) -> bytes:
    """Try the packet structure as if hops comes after transport_id for header_type=1"""
    header_type = (packetBytes[0] >> 6) & 0b11
    hashable_part = bytes([packetBytes[0] & 0b00001111])

    if header_type == 1:
        # What if the structure is: header, transport_id[0], hops, rest?
        hashable_part += bytes(
            [packetBytes[1]]
        )  # First byte of what we thought was hops
        hashable_part += packetBytes[3:]  # Skip actual hops position
    else:
        hashable_part += packetBytes[2:]

    return hashlib.sha256(hashable_part).digest()


# Test with the problematic packet
packet_hex = "71014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308"
packet = bytes.fromhex(packet_hex)

print(f"Packet analysis:")
print(f"  Header byte: 0x{packet[0]:02x} (header_type={(packet[0] >> 6) & 0b11})")
print(f"  Byte 1 (hops?): 0x{packet[1]:02x}")
print(f"  Bytes 2-17 (transport_id?): {packet[2:18].hex()}")
print(f"  Bytes 18-33 (destination?): {packet[18:34].hex()}")
print()

expected_hash = "b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77"
print(f"Expected hash: {expected_hash}")
print()

# Try all methods
methods = [
    ("Original", get_message_id_original),
    ("Skip transport_id", get_message_id_skip_transport_id),
    ("Reorder transport_id", get_message_id_reorder_transport_id),
    ("Exclude hops", get_message_id_exclude_hops),
    ("Special ordering", get_message_id_special_ordering),
]

for name, method in methods:
    hash_result = method(packet)
    hash_hex = hash_result.hex()
    match = "✓ MATCH!" if hash_hex == expected_hash else "✗"
    print(f"{name:20}: {hash_hex} {match}")

# Let's also try to understand the packet structure better
print("\n" + "=" * 80 + "\n")
print("Detailed packet structure analysis:")
print(f"Position 0x00: 0x{packet[0]:02x} (header)")
print(f"Position 0x01: 0x{packet[1]:02x}")
print(f"Position 0x02: 0x{packet[2]:02x}")

# Look for the destination hash pattern in the packet
destination_from_test = "acd4eef4901f2b7c69e761dc8781ed4c"
dest_bytes = bytes.fromhex(destination_from_test)
dest_hex = dest_bytes.hex()

print(f"\nSearching for destination hash: {destination_from_test}")
for i in range(len(packet) - 16):
    if packet[i : i + 16].hex() == dest_hex:
        print(f"  Found at position {i} (0x{i:02x})")

# Also check if hops byte is elsewhere
print("\nLooking for potential hops byte (0x4a) locations:")
for i, b in enumerate(packet):
    if b == 0x4A:
        print(f"  Found 0x4a at position {i} (0x{i:02x})")
