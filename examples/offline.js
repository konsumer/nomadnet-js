// manually offline parsing real traffic (between 2 official clients) using real keys

import { bytesToHex } from '@noble/curves/utils.js'
import { loadPacket, parseAnnounce, decryptMessage, unserializeIdentity, pubFromPrivate, getLxmfIdentity, PACKET_ANNOUNCE, PACKET_DATA, PACKET_PROOF } from '../src/index.js'
import { keys, ratchets, packets } from './demo_data.js'

const identities = {
  clientA: unserializeIdentity(keys.clientA),
  clientB: unserializeIdentity(keys.clientA)
}
identities.clientA = { ...identities.clientA, ...pubFromPrivate(identities.clientA) }
identities.clientB = { ...identities.clientB, ...pubFromPrivate(identities.clientB) }
identities.clientA = { ...identities.clientA, ...getLxmfIdentity(identities.clientA) }
identities.clientB = { ...identities.clientB, ...getLxmfIdentity(identities.clientB) }

for (const p of packets) {
  const packet = loadPacket(p)
  if (packet.packetType === PACKET_ANNOUNCE) {
    const announce = parseAnnounce(packet)
    console.log(`ANNOUNCE (${bytesToHex(packet.destinationHash)})\n  ${announce.verified ? 'Valid' : 'Invalid'}`)
  }
  if (packet.packetType === PACKET_DATA) {
    let identity = identities.clientA
    if (bytesToHex(identities.clientB.destinationHash) === bytesToHex(packet.destinationHash)) {
      identity = identities.clientB
    }
    const message = await decryptMessage(packet, identity.encPub, ratchets)
    console.log(`DATA (${bytesToHex(packet.destinationHash)})`)
    console.log(message)
  }
  if (packet.packetType === PACKET_PROOF) {
    console.log(`PROOF (${bytesToHex(packet.destinationHash)})`)
  }
}
