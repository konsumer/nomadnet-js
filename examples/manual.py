import demo_data
import RNS

# this loads a Packet, with no side-effects 
def load_packet(raw):
  packet = RNS.Packet.__new__(RNS.Packet)
  packet.raw = raw
  RNS.Packet.unpack(packet)
  return packet

# parse an announce packet: similar to RNS.Identity.validate_announce, but returns the useful parts
def process_announce(packet):
    keysize       = RNS.Identity.KEYSIZE//8
    ratchetsize   = RNS.Identity.RATCHETSIZE//8
    name_hash_len = RNS.Identity.NAME_HASH_LENGTH//8
    sig_len       = RNS.Identity.SIGLENGTH//8
    destination_hash = packet.destination_hash
    public_key = packet.data[:keysize]
    if packet.context_flag == RNS.Packet.FLAG_SET:
        name_hash   = packet.data[keysize:keysize+name_hash_len ]
        random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
        ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
        signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
            app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
    else:
        ratchet     = b""
        name_hash   = packet.data[keysize:keysize+name_hash_len]
        random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
        signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len:
            app_data = packet.data[keysize+name_hash_len+10+sig_len:]
    signed_data = destination_hash+public_key+name_hash+random_hash+ratchet+app_data
    
    if not len(packet.data) > RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8+10+RNS.Identity.SIGLENGTH//8:
        app_data = None
    
    announced_identity = RNS.Identity(create_keys=False)
    announced_identity.load_public_key(public_key)
    return {
        'identity': announced_identity,
        'ratchet': ratchet,
        'name_hash': name_hash,
        'random_hash': random_hash,
        'signature': signature,
        'app_data': app_data,
        'signed_data': signed_data,
        'packet': packet
    }

# parse & decrypt DATA packet with recipient identity (private & public key) & stored announce identities (pubkey, ratchet info, etc)
def process_data(packet, recipient, announces):
    """
    Final check: maybe the packet DOESN'T use ratchets.
    Let's compare the ephemeral key with recipient's public key.
    """
    
    ephemeral_pub_bytes = packet.data[:32]
    
    print(f"=== Key Comparison ===")
    print(f"Ephemeral key: {ephemeral_pub_bytes.hex()}")
    print(f"Recipient encryption pub: {recipient.pub_bytes.hex()}")
    print(f"Recipient signing pub: {recipient.sig_pub_bytes.hex()}")
    
    # Get recipient announce
    recipient_announce = announces.get(packet.destination_hash)
    if recipient_announce:
        recipient_ratchet = recipient_announce.get('ratchet')
        print(f"Recipient ratchet pub: {recipient_ratchet.hex()}")
    
    # The encryption logs showed derived_key was 64 bytes
    # Token only accepts 16 or 32 bytes (128 or 256 bits)
    # So the 64-byte derived key must be SPLIT:
    # - First 32 bytes: encryption key
    # - Second 32 bytes: HMAC key (or vice versa)
    
    print(f"\n=== Trying with 64-byte derived key split ===")
    
    # Use standard identity ECDH (not ratchet)
    peer_pub = RNS.Cryptography.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_key = recipient.prv.exchange(peer_pub)
    
    derived_key_64 = RNS.Cryptography.hkdf(
        length=64,  # Get full 64 bytes
        derive_from=shared_key,
        salt=recipient.get_salt(),
        context=recipient.get_context()
    )
    
    print(f"Derived key (64 bytes): {derived_key_64.hex()}")
    
    # Try both halves as the Token key
    for split_name, key_portion in [("first 32", derived_key_64[:32]), ("second 32", derived_key_64[32:])]:
        print(f"\nTrying with {split_name} bytes: {key_portion.hex()}")
        
        try:
            token = RNS.Cryptography.Token(key_portion)
            ciphertext = packet.data[32:]
            plaintext = token.decrypt(ciphertext)
            
            print(f"✓✓✓ SUCCESS with {split_name}! ✓✓✓")
            print(f"Plaintext: {plaintext}")
            return {'plaintext': plaintext, 'packet': packet}
        except Exception as e:
            print(f"Failed: {e}")
    
    raise ValueError("Cannot decrypt")



clientA = RNS.Identity.from_bytes(demo_data.keys['clientA'])
clientB = RNS.Identity.from_bytes(demo_data.keys['clientB'])
clientA_addr = RNS.Destination.hash(clientA, "lxmf", "delivery")
clientB_addr = RNS.Destination.hash(clientB, "lxmf", "delivery")

identities = {
    clientA_addr: clientA,
    clientB_addr: clientB
}

print(f"Client A LXMF Address: {clientA_addr.hex()}")
print(f"Client B LXMF Address: {clientB_addr.hex()}")

# this will hold parsed ANNOUNCE packets (pubkeys and  other info)
held_announces = {}

for p in demo_data.packets:
    packet = load_packet(p)
    
    if packet.packet_type == RNS.Packet.ANNOUNCE:
        print(f"ANNOUNCE ({packet.destination_hash.hex()})")
        if RNS.Identity.validate_announce(packet, True):
            held_announces[ packet.destination_hash ] = process_announce(packet)
            print("  Added announce")
        else:
            print("  Skipped (invalid)")
    
    if packet.packet_type == RNS.Packet.DATA:
        print(f"DATA ({packet.destination_hash.hex()})")
        try:
            recipient = identities[packet.destination_hash]
            print(process_data(packet, recipient, held_announces))

        except Exception as e:
            print(f"  Error: {e}")
    
    if packet.packet_type == RNS.Packet.PROOF:
        print(f"PROOF ({packet.destination_hash.hex()})")


