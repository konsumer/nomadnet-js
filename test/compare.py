#!/usr/bin/env python3

"""
Use this to compare output/interop with js
"""

import RNS
import LXMF
import json
import sys

def RNS_packet_unpack(raw):
    """Load a packet from raw bytes without side effects"""
    packet = RNS.Packet.__new__(RNS.Packet)
    packet.raw = raw
    RNS.Packet.unpack(packet)
    packet.rssi = None
    packet.snr = None
    packet.receiving_interface = None
    return packet

def RNS_destination_from_identity(identity, direction, type, app_name, *aspects):
    """Create a Destination from an Identity without side effects"""
    destination = RNS.Destination.__new__(RNS.Destination)
    destination.accept_link_requests = True
    destination.request_handlers = {}
    destination.direction = direction
    destination.type = type
    destination.proof_strategy = RNS.Destination.PROVE_NONE
    destination.mtu = 0
    destination.links = []
    destination.identity = identity
    destination.name = RNS.Destination.expand_name(identity, app_name, *aspects)
    destination.hash = RNS.Destination.hash(identity, app_name, *aspects)
    destination.name_hash = RNS.Identity.full_hash(
        RNS.Destination.expand_name(None, app_name, *aspects).encode("utf-8")
    )[:(RNS.Identity.NAME_HASH_LENGTH//8)]
    destination.hexhash = destination.hash.hex()
    destination.default_app_data = None
    destination.callback = None
    destination.proofcallback = None
    return destination

op = sys.argv[1]
args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

# me: 76a93cda889a8c0a88451e02d53fd8b9
identityBytes = bytes.fromhex("e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd")
identity = RNS.Identity(create_keys=False)
identity.load_private_key(identityBytes)
identityDest = RNS_destination_from_identity(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")

# them: 072ec44973a8dee8e28d230fb4af8fe4
otherBytes = bytes.fromhex("205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313")
other = RNS.Identity(create_keys=False)
other.load_private_key(otherBytes)
otherDest = RNS_destination_from_identity(other, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")

try:
    if op == "idcheck":
        out = {
            "me": identityDest.hexhash,
            "other": otherDest.hexhash
        }
        print(json.dumps(out))
    
    elif op == "verifyAnnounce":
        # Python verifies a JS-created announce
        packet = RNS_packet_unpack(bytes.fromhex(args))
        print(json.dumps({
            "valid": RNS.Identity.validate_announce(packet),
            "hash": packet.destination_hash.hex()
        }))

    elif op == "announce":
        identityDest.path_responses = []
        identityDest.ratchets = None
        identityDest.path_responses = {}
        p=identityDest.announce(send=False, tag="test")
        print(identityDest.path_responses)
        p.unpack()
        print(json.dumps({"packet": p.raw.hex()}))
    
    elif op == "createProof":
        # Python creates a PROOF for a DATA packet from JS
        packet_bytes = bytes.fromhex(args['packet'])
        packet = RNS_packet_unpack(packet_bytes)
        
        # Sign the packet hash
        signature = identity.sign(packet.packet_hash)
        
        # Create PROOF packet
        # Proof destination is first 16 bytes of packet hash
        proof_dest = packet.packet_hash[:16]
        proof_header = (0b00000011 << 6) | 0b00000000  # PROOF packet, no flags
        proof_raw = bytes([proof_header]) + proof_dest + signature
        
        print(json.dumps({
            "proof": proof_raw.hex(),
            "packetHash": packet.packet_hash.hex()
        }))
    
    elif op == "verifyProof":
        # Python verifies a PROOF packet from JS
        proof_bytes = bytes.fromhex(args['proof'])
        proof_packet = RNS_packet_unpack(proof_bytes)
        
        original_bytes = bytes.fromhex(args['originalPacket'])
        original_packet = RNS_packet_unpack(original_bytes)
        
        # Verify signature
        signature = proof_packet.data
        valid = other.validate(signature, original_packet.packet_hash)
        
        print(json.dumps({
            "valid": valid
        }))
    
    elif op == "createData":
        # Python creates a DATA packet to send to JS
        data_content = args.get('data', 'Hello from Python').encode('utf-8')
        
        # Build DATA packet to otherDest
        header = (0b00000000 << 6) | 0b00000000  # DATA packet
        packet_raw = bytes([header]) + otherDest.hash + data_content
        
        print(json.dumps({
            "packet": packet_raw.hex()
        }))
    
    elif op == "verifyData":
        # Python verifies a DATA packet from JS
        packet_bytes = bytes.fromhex(args['packet'])
        packet = RNS_packet_unpack(packet_bytes)
        
        # Check if destination matches
        dest_match = packet.destination_hash == identityDest.hash
        
        print(json.dumps({
            "valid": dest_match,
            "destinationHash": packet.destination_hash.hex(),
            "data": packet.data.hex()
        }))

except Exception as e:
    import traceback
    print(json.dumps({
        "error": str(e),
        "traceback": traceback.format_exc()
    }), file=sys.stderr)
    sys.exit(1)
