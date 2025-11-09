#!/usr/bin/env python3
import hashlib


def get_message_id(packetBytes: bytes) -> bytes:
    """
    Get the message-id (used as destination in PROOFs, for example) from a packet
    """
    hashable_part = bytes([packetBytes[0] & 0b00001111])
    hashable_part += packetBytes[2:]
    return hashlib.sha256(hashable_part).digest()


# Test packet from the failing test
packet_hex = "71014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308"
packet = bytes.fromhex(packet_hex)

print(f"Packet length: {len(packet)}")
print(f"First byte: {packet[0]} = 0x{packet[0]:02x} = 0b{packet[0]:08b}")
print(
    f"First byte & 0b00001111: {packet[0] & 0b00001111} = 0x{packet[0] & 0b00001111:02x}"
)
print()

# Build hashable part
hashable_part = bytes([packet[0] & 0b00001111])
hashable_part += packet[2:]

print(f"Hashable part first byte: 0x{hashable_part[0]:02x}")
print(f"Hashable part length: {len(hashable_part)}")
print(f"Hashable part hex: {hashable_part.hex()}")
print()

# Calculate hash
message_id = get_message_id(packet)
print(f"Calculated message_id: {message_id.hex()}")
print(
    f"Expected packet_hash: b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77"
)

# Let's also test the first packet which is passing
print("\n" + "=" * 80 + "\n")
print("Testing first packet (which passes):")
packet1_hex = "2100072ec44973a8dee8e28d230fb4af8fe400a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece6ec60bc318e2c0f0d90873408275530068de1039e2bb21108b2cbc900b476290ab7867441446db366a70fb8ed1448ca0e889bd65bad6d8654e72661ddc089b06495ab91a57afc5700e095f021aa8cec04f22ba55438efc3ab1e2a91b8d17bd259313f175dff040827fdf1111c88bef501676380b92c40e416e6f6e796d6f75732050656572c0"
packet1 = bytes.fromhex(packet1_hex)

print(f"Packet1 first byte: {packet1[0]} = 0x{packet1[0]:02x} = 0b{packet1[0]:08b}")
print(
    f"Packet1 first byte & 0b00001111: {packet1[0] & 0b00001111} = 0x{packet1[0] & 0b00001111:02x}"
)

message_id1 = get_message_id(packet1)
print(f"Calculated message_id: {message_id1.hex()}")
print(
    f"Expected packet_hash: e56755f8b7405b07c12a5c25d7b9b744ca296f7349768b335c78be868530b57d"
)
