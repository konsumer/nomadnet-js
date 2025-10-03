// this will create a message to read from python (to test JS encryption) use decrypt_message.py to check

import { bytesToHex } from '@noble/curves/utils.js'
import { unserializeIdentity, buildMessage, loadPacket, processMessage } from '../src/index.js'
import { keys, ratchets } from './demo_data.js'

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)
const identities = {
  [clientA.destinationHash]: clientA,
  [clientB.destinationHash]: clientB
}

console.log('Client A LXMF Address:', bytesToHex(clientA.destinationHash))
console.log('Client B LXMF Address:', bytesToHex(clientB.destinationHash))

const messageBytes = buildMessage({ content: 'Hello from Javascript!' }, clientA.destinationHash, ratchets[0], clientA.identityHash)

console.log('Paste this in decrypt_message.py:')
console.log(bytesToHex(messageBytes))

const packet = loadPacket(messageBytes)
// console.log('\nHere is packet:')
// console.log(packet)

const parsed = processMessage(packet, identities[packet.destinationHash], ratchets)
console.log('\nHere is decrypted:')
console.log(parsed)
