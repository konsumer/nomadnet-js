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

