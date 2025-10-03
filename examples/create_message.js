// this will create a message to read from python (to test JS encryption) use decrypt_message.py to check

import { bytesToHex } from '@noble/curves/utils.js'
import { unserializeIdentity, buildData, loadPacket, processData } from '../src/index.js'
import { keys, ratchets } from './demo_data.js'

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)

console.log('Client A LXMF Address:', bytesToHex(clientA.destinationHash))
console.log('Client B LXMF Address:', bytesToHex(clientB.destinationHash))

const messageBytes = buildData({ content: 'Hello from Javascript!' }, clientA.destinationHash, ratchets[0], clientA.identityHash)

console.log('Paste this in decrypt_message.py:')
console.log(bytesToHex(messageBytes))

// I can;t decrypt my own packet, so there is some other subtle problem
// console.log('\nHere it is decrypted:')
// const packet = loadPacket(messageBytes)
// const parsed = processData(packet, client, ratchets)
// console.log(parsed)
