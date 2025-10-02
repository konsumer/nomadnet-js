import demo_data
import RNS
import threading

# this loads a Packet, with no side-effects 
def load_packet(raw):
  packet = RNS.Packet.__new__(RNS.Packet)
  packet.raw = raw
  RNS.Packet.unpack(packet)
  packet.rssi = None
  packet.snr = None
  packet.receiving_interface = None
  return packet

# load a destination, with no side-effects 
def load_destination(identity, direction, type, app_name, *aspects):
    dest = RNS.Destination.__new__(RNS.Destination)
    dest.accept_link_requests = True
    dest.request_handlers = {}
    dest.type = type
    dest.direction = direction
    dest.proof_strategy = RNS.Destination.PROVE_NONE
    dest.ratchets = None
    dest.ratchets_path = None
    dest.ratchet_interval = RNS.Destination.RATCHET_INTERVAL
    dest.ratchet_file_lock = threading.Lock()
    dest.retained_ratchets = RNS.Destination.RATCHET_COUNT
    dest.latest_ratchet_time = None
    dest.latest_ratchet_id = None
    dest.__enforce_ratchets = False
    dest.mtu = 0

    dest.path_responses = {}
    dest.links = []

    if identity == None and direction == RNS.Destination.IN and dest.type != RNS.Destination.PLAIN:
        identity = RNS.Identity()
        aspects = aspects+(identity.hexhash,)

    if identity == None and direction == RNS.Destination.OUT and dest.type != RNS.Destination.PLAIN:
        raise ValueError("Can't create outbound SINGLE destination without an identity")

    if identity != None and dest.type == RNS.Destination.PLAIN:
        raise TypeError("Selected destination type PLAIN cannot hold an identity")

    dest.identity = identity
    dest.name = RNS.Destination.expand_name(identity, app_name, *aspects)

    # Generate the destination address hash
    dest.hash = RNS.Destination.hash(dest.identity, app_name, *aspects)
    dest.name_hash = RNS.Identity.full_hash(dest.expand_name(None, app_name, *aspects).encode("utf-8"))[:(RNS.Identity.NAME_HASH_LENGTH//8)]
    dest.hexhash = dest.hash.hex()

    dest.default_app_data = None
    dest.callback = None
    dest.proofcallback = None
    return dest

# parse an announce packet and add to RNS.Identity.known_ratchets
def process_announce(packet):
    keysize       = RNS.Identity.KEYSIZE//8
    ratchetsize   = RNS.Identity.RATCHETSIZE//8
    name_hash_len = RNS.Identity.NAME_HASH_LENGTH//8
    destination_hash = packet.destination_hash
    public_key = packet.data[:keysize]
    if packet.context_flag == RNS.Packet.FLAG_SET:
        ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
    else:
        ratchet     = b""
    RNS.Identity.known_ratchets[destination_hash] = ratchet



# parse & decrypt DATA packet with recipient identity (private & public key) & stored announce identities (pubkey, ratchet info, etc)
def process_data(packet, recipient):
    decryptedBytes = recipient.identity.decrypt(packet.data, ratchets=demo_data.ratchets)
    return RNS.vendor.umsgpack.unpackb(decryptedBytes[80:])
    


clientA = RNS.Identity.from_bytes(demo_data.keys['clientA'])
clientB = RNS.Identity.from_bytes(demo_data.keys['clientB'])
clientA_addr = RNS.Destination.hash(clientA, "lxmf", "delivery")
clientB_addr = RNS.Destination.hash(clientB, "lxmf", "delivery")
recipient_destinations = {
    clientA_addr: load_destination(clientA, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"),
    clientB_addr: load_destination(clientB, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
}

print(f"Client A LXMF Address: {recipient_destinations[clientA_addr].hexhash}")
print(f"Client B LXMF Address: {recipient_destinations[clientB_addr].hexhash}")

for p in demo_data.packets:
    packet = load_packet(p)
    
    if packet.packet_type == RNS.Packet.ANNOUNCE:
        print(f"ANNOUNCE ({packet.destination_hash.hex()})")
        if RNS.Identity.validate_announce(packet, True):
            process_announce(packet)
            print("  Added announce")
        else:
            print("  Skipped (invalid)")
    
    if packet.packet_type == RNS.Packet.DATA:
        print(f"DATA ({packet.destination_hash.hex()})")
        try:
            recipient = recipient_destinations[packet.destination_hash]
            ts, title, content, fields = process_data(packet, recipient)
            print(f"  Received message:\n  {content.decode('utf8')}")

        except Exception as e:
            print(f"  Error: {e}")
    
    if packet.packet_type == RNS.Packet.PROOF:
        print(f"PROOF ({packet.destination_hash.hex()})")


