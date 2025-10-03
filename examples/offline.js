// manually offline parsing real traffic (between 2 official clients) using real keys

import { bytesToHex } from '@noble/curves/utils.js'
import { loadPacket, parseAnnounce, decryptMessage, unserializeIdentity, byteCompare, PACKET_ANNOUNCE, PACKET_DATA, PACKET_PROOF } from '../src/index.js'
import { keys, ratchets, packets } from './demo_data.js'

const indentString = (str='', indentLevel = 1, indentChar = '  ') => str.split('\n').map(line => indentChar.repeat(indentLevel) + line).join('\n');

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)

// since there are only 2 peers, this just lets you pick the "other one"
const other = {
  [clientB.destinationHash]: clientA,
  [clientA.destinationHash]: clientB
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
    const message = await decryptMessage(packet, other[packet.destinationHash], ratchets)
    console.log(`DATA (${bytesToHex(packet.destinationHash)})`)
    console.log('  Received message:')
    console.log(indentString(message || 'None', 2))
  }

  if (packet.packetType === PACKET_PROOF) {
    console.log(`PROOF (${bytesToHex(packet.destinationHash)})`)
  }
}
