// manually offline parsing real traffic (between 2 official clients) using real keys

import { bytesToHex } from '@noble/curves/utils.js'
import { loadPacket, parseAnnounce, processData, identityDecrypt, unserializeIdentity, byteCompare, PACKET_ANNOUNCE, PACKET_DATA, PACKET_PROOF } from '../src/index.js'
import { keys, ratchets, packets } from './demo_data.js'
import { inspect } from 'node:util'

import { concatBytes } from '@noble/curves/utils.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { cbc } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { unpack, pack } from 'msgpackr'

const indentString = (str = '', indentLevel = 1, indentChar = '  ') =>
  str
    .split('\n')
    .map((line) => indentChar.repeat(indentLevel) + line)
    .join('\n')

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)

const identities = {
  [clientA.destinationHash]: clientA,
  [clientB.destinationHash]: clientB
}

console.log(`Client A LXMF Address: ${bytesToHex(clientA.destinationHash)}`)
console.log(`Client B LXMF Address: ${bytesToHex(clientB.destinationHash)}`)

const decoder = new TextDecoder()

for (const p of packets) {
  const packet = loadPacket(p)
  if (packet.packetType === PACKET_ANNOUNCE) {
    const announce = parseAnnounce(packet)
    console.log(`ANNOUNCE (${bytesToHex(packet.destinationHash)})\n  ${announce.verified ? 'Valid' : 'Invalid'}`)
    console.log(`  Ratchet Pub(${announce.ratchetPub.length}): ${bytesToHex(announce.ratchetPub)}`)
    console.log(`  Signature(${announce.signature.length}): ${bytesToHex(announce.signature)}`)
    console.log(indentString(`App Data: ${inspect(announce.appData, null, 2)}`))
  }

  if (packet.packetType === PACKET_DATA) {
    const { timestamp, title, content } = processData(packet, identities[packet.destinationHash], ratchets)
    console.log(`DATA (${bytesToHex(packet.destinationHash)})`)
    console.log('  Received message:')
    console.log(indentString(`Time: ${new Date(timestamp * 1000)}\nTitle: ${decoder.decode(title)}\nContent: ${decoder.decode(content)}`, 2))
  }

  if (packet.packetType === PACKET_PROOF) {
    console.log(`PROOF (${bytesToHex(packet.destinationHash)})`)
  }
}
