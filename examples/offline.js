// manually offline parsing real traffic (between 2 official clients) using real keys

import { bytesToHex } from '@noble/curves/utils.js'
import { loadPacket, parseAnnounce, decryptMessage, unserializeIdentity, byteCompare, PACKET_ANNOUNCE, PACKET_DATA, PACKET_PROOF } from '../src/index.js'
import { keys, ratchets, packets } from './demo_data.js'

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)
const identities = {
  [clientA.destinationHash]: clientA,
  [clientB.destinationHash]: clientB
}

console.log(`Client A LXMF Address: ${bytesToHex(clientA.destinationHash)}`)
console.log(`Client B LXMF Address: ${bytesToHex(clientB.destinationHash)}`)

for (const p of packets) {
  const packet = loadPacket(p)
  if (packet.packetType === PACKET_ANNOUNCE) {
    const announce = parseAnnounce(packet)
    console.log(`ANNOUNCE (${bytesToHex(packet.destinationHash)})\n  ${announce.verified ? 'Valid' : 'Invalid'}`)
  }

  if (packet.packetType === PACKET_DATA) {
    const identity = identities[packet.destinationHash]
    const message = await decryptMessage(packet, identity, ratchets)
    console.log(`DATA (${bytesToHex(packet.destinationHash)})`)
    console.log(message)
  }

  if (packet.packetType === PACKET_PROOF) {
    console.log(`PROOF (${bytesToHex(packet.destinationHash)})`)
  }
}
