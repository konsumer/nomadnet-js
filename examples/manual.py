# this will manually decrypt a reticulum packet using RNS and real data pulled from traffic & storage-files

# there are 2 peers: 4f55a90bda8fc8b2ff6db3b9b35005f0 and 4ffdfafcd44675dfa6e03393ffdedc87

import RNS
import msgpack

# simple util to load a  Packet from hex-string (without transport side-effects)
def load_packet(hexString):
  packet = RNS.Packet.__new__(RNS.Packet)
  packet.raw = bytes.fromhex(hexString)
  RNS.Packet.unpack(packet)
  return packet


# similar to Identity.validate_announce ratchet-stuff, without transport side-effects
def get_ratchet(packet):
  keysize       = RNS.Identity.KEYSIZE//8
  ratchetsize   = RNS.Identity.RATCHETSIZE//8
  name_hash_len = RNS.Identity.NAME_HASH_LENGTH//8
  destination_hash = packet.destination_hash
  return packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]


# similar to Identity.decrypt, but with better errors
def decrypt(identity, ciphertext_token):
  if identity.prv == None:
    RNS.log("Decryption failed because identity does not hold a private key", RNS.LOG_DEBUG)
    return None
  if len(ciphertext_token) <= RNS.Identity.KEYSIZE//8//2:
    RNS.log("Decryption failed because the token size was invalid.", RNS.LOG_DEBUG)
    return None
  peer_pub_bytes = ciphertext_token[:RNS.Identity.KEYSIZE//8//2]
  peer_pub = RNS.Cryptography.X25519PublicKey.from_public_bytes(peer_pub_bytes)
  ciphertext = ciphertext_token[RNS.Identity.KEYSIZE//8//2:]
  # try all ratchets
  for r in RNS.Identity.known_ratchets:
    ratchet = RNS.Identity.known_ratchets[r]
    ratchet_prv = RNS.Cryptography.X25519PrivateKey.from_private_bytes(ratchet)
    ratchet_id = RNS.Identity._get_ratchet_id(ratchet_prv.public_key().public_bytes())
    shared_key = ratchet_prv.exchange(peer_pub)
    
    derived_key = RNS.Cryptography.hkdf(
        length=RNS.Identity.DERIVED_KEY_LENGTH,
        derive_from=shared_key,
        salt=identity.get_salt(),
        context=identity.get_context())
    try:
      token = RNS.Cryptography.Token(derived_key)
      plaintext = token.decrypt(ciphertext)
      return plaintext
    except Exception as e:
      print(f"Ratchet: {r.hex()}: {e}")
      pass



# this comes from nomad/storage/identity
idBytes = [
  bytes.fromhex('081a5e6bef228982e4b06f3df1b6c1dc7975fa7e27082b6564f5d0a96c644f4de47251da287ae3a87db9cbab4707816a2d761f1371399ee1690be7b7ee0cbbb2'),
  bytes.fromhex('40081d522aa9ad55c776ee552d1f4a4ee1c934b0f23c0c049f3b602e82fd977650c9e6e2a903c0a52b746a7869b38f45069cadfe716aabe1392f2e17e49b92a1')
]
identities = {}
for i in idBytes:
  idx = RNS.Identity.from_bytes(i)
  identities[ RNS.Destination.hash(idx, "lxmf", "delivery") ] = idx


# this was captured from traffic
packets = [
  load_packet('21004f55a90bda8fc8b2ff6db3b9b35005f000e0eec6696d6ef606b1919c86dafbf8b10d076c9f33e80319f6f41db0aa17d32a08fa2ed0ab67a5957fe52fcb907a6a1a4e04b1c8682daf78e0d451058d7c4e146ec60bc318e2c0f0d908a584e315310068d9c8125037bc6886277fe78696d3458dce1757ae904f340e1ea479e5d0e3e1b16e7819a9fa21c1cc20b037e8ef283de393fd65e1b04370dfcc3761aae4f5387b42a44399d930dbaa9643c55439665c6a17e7f858e91616f43fd3819680c640f070610192c40e416e6f6e796d6f75732050656572c0'),
  load_packet('21004ffdfafcd44675dfa6e03393ffdedc8700352b4efa2a28bc3c97cd3405c0ccad16b70ea5b17334c1f7520727103b788a4a489824577f21588530e6f7b85421ac678193d5f749aa54e1e8c970924b4d8c5d6ec60bc318e2c0f0d9086e71fe30530068d9c81c235b81149f324b9f1febec01b5c709cece4426626712acff24ca871eac1431264ad1ff8b5dd999f270a2b092a27d777c6f7834b2873453b327e233f23a33b379826e45f4827128e973eedf66aade31464d94efbb80e4444393e76534d8ce360692c40e416e6f6e796d6f75732050656572c0'),
  load_packet('00004ffdfafcd44675dfa6e03393ffdedc87007fd42a64baebe5a643afd7175d80e02d42a77b92c2be01dc64a063019de7a5204029544be7545d65ebb88c266065e27cb8fdcf4d2e68416783f7d0620345cd4dacdd8dd0ac27e8ad2d4e198ee33ae71ba40802f2eb201b49cdb389ef8c6e4949bb7ac948613df3f3b686c148d78d91681cf69f9da27b92ba122dca645b79346155bce8a1fa5015e9d6b397645883fb020a0e43a87a4a32a386882ea6b5aa03c7f0d28ee04bb0f354180d8fddc5415b3328a250f05f8a9563bb626a9804e3aedf'),
  load_packet('03002cc5ec7b99fcd8e4c82f21accbe3421e008c25bb546be1c78c6f78c4017ead9c10b8e81b1de937098c0ef4c380144308c950699fd8a889e029a242225983aef4cf952853b6a1be5df068ad7f30d6fa7c01'),
  load_packet('00004f55a90bda8fc8b2ff6db3b9b35005f000e5678441c78799543fc642553b72cff136a839258c76a49cd37f40edd5f1f01e68a514f3be0ef894e4959ab3d28d21cfd25fba78378b921b9aff5c225aedcd9db9ea4d084a6d3417f846e175cdec0d5c04ce157fefb13f677bdb8080e56f94bd30370838ce288a42e8eadbfb5066f2198ea401fa7e7e18f20848ab05134750ca9c06dcfc830a78b2ac79d4fc2100df44078ca8e51e124a9c077c889966a4035bd6a74f16701fc3108be29f121f21326a5940918d9d7cd28d9ed2af6facc0e050'),
  load_packet('0300c094520762dc17144f879fe589e340ad001be96da381b0be4bbb438cda6112b8e095aff8417f8bf65690746b199d3984c7183e66d68764d2e56f99988569594116f7179ffae0c97cb27026c80ae23a280e')
]

typeNames = {
  RNS.Packet.DATA: "DATA",
  RNS.Packet.ANNOUNCE: "ANNOUNCE",
  RNS.Packet.LINKREQUEST: "LINK",
  RNS.Packet.PROOF : "PROOF"
}

destNames = {
  RNS.Destination.SINGLE: "SINGLE",
  RNS.Destination.GROUP: "GROUP",
  RNS.Destination.PLAIN: "PLAIN",
  RNS.Destination.LINK: "LINK"
}

for packet in packets:
  dest = packet.destination_hash.hex()
  print(f'Packet Destination: {dest}')
  print(f"Packet type: {typeNames[packet.packet_type]}")
  print(f"Packet hash: {packet.packet_hash.hex()}")
  print(f"Destination type: {destNames[packet.destination_type]}")
  print(f"Destination hash: {packet.destination_hash.hex()}")

  # parse announce packets and collect ratchets
  if packet.packet_type == RNS.Packet.ANNOUNCE:
    valid = RNS.Identity.validate_announce(packet, True)
    if valid:
      print("Valid: Yes")
      if packet.context_flag == RNS.Packet.FLAG_SET:
        RNS.Identity.known_ratchets[packet.destination_hash] = get_ratchet(packet)
        print("Ratchet:", RNS.Identity.known_ratchets[packet.destination_hash].hex())
      else:
        print("Ratchet: No")
    else:
      print("Valid: No")

  # decrypt data  using ratchets & private key
  if packet.packet_type == RNS.Packet.DATA:
    for idx in identities:
      if idx == packet.destination_hash:
        recipientId = identities[idx]
        # This gives me "Token HMAC was invalid" for all ratchets, so I must be doing it wrong
        contents = decrypt(recipientId, packet.data)
        print("Decrypted:", contents)

  print("")
