import demo_data
import RNS
import textwrap

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
    # TODO: generate a ratchet for this destination
    pass


# parse & decrypt DATA packet with recipient identity (private & public key) & ratchets
def process_data(packet, identity):
    decryptedBytes = identity.decrypt(packet.data, ratchets=demo_data.ratchets)
    return RNS.vendor.umsgpack.unpackb(decryptedBytes[80:])


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

for p in demo_data.packets:
    packet = load_packet(p)
    
    if packet.packet_type == RNS.Packet.ANNOUNCE:
        print(f"ANNOUNCE ({packet.destination_hash.hex()})")
        if RNS.Identity.validate_announce(packet, True):
            process_announce(packet)
            print("  Valid")
        else:
            print("  Invalid")
    
    if packet.packet_type == RNS.Packet.DATA:
        print(f"DATA ({packet.destination_hash.hex()})")
        try:
            ts, title, content, fields = process_data(packet, identities[packet.destination_hash])
            print(f"  Received message:\n{textwrap.indent(content.decode('utf8'), '    ')}")

        except Exception as e:
            print(f"  Error: {e}")
    
    if packet.packet_type == RNS.Packet.PROOF:
        print(f"PROOF ({packet.destination_hash.hex()})")


