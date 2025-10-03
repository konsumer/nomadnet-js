// this will create a message to read from python (to test JS encryption) use decrypt_message.py to check

import { bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { unserializeIdentity, encryptData, buildPacket, PACKET_DATA, DESTINATION_SINGLE, PROPOGATION_BROADCAST, CONTEXT_NONE } from '../src/index.js'
import { pack } from 'msgpackr'
import { x25519 } from '@noble/curves/ed25519.js'

// Your existing keys
export const keys = {
  clientA: '205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313',
  clientB: 'e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd'
}

export const ratchets = [hexToBytes('205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066'), hexToBytes('28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45')]

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)

console.log('Client A LXMF Address:', bytesToHex(clientA.destinationHash))
console.log('Client B LXMF Address:', bytesToHex(clientB.destinationHash))

// === CREATE ENCRYPTED MESSAGE FROM B TO A ===

const message = {
  title: '',
  content: 'Hello from JavaScript!',
  fields: {}
}

// Prepare message data
const timestamp = Date.now() / 1000
const titleBytes = new Uint8Array([])
const contentBytes = new TextEncoder().encode(message.content)
const messageData = pack([timestamp, titleBytes, contentBytes, message.fields])

// Add 80-byte header
const header = new Uint8Array(80)
const plaintext = new Uint8Array([...header, ...messageData])

// Derive PUBLIC key from the ratchet PRIVATE key
const recipientRatchetPriv = ratchets[0] // This is the private key
const recipientRatchetPub = x25519.getPublicKey(recipientRatchetPriv) // Derive public key

console.log('Encrypting to ratchet public key:', bytesToHex(recipientRatchetPub))

const recipientIdentityHash = clientA.identityHash
const recipientDestinationHash = clientA.destinationHash

const encryptedData = encryptData(plaintext, recipientRatchetPub, recipientIdentityHash)

// Build complete DATA packet
const dataPacket = {
  ifac: 0,
  headerType: 0,
  contextFlag: 0,
  propogationType: 0,
  destinationType: 0,
  packetType: 0,
  hops: 0,
  destinationHash: recipientDestinationHash,
  context: 0,
  data: encryptedData
}

const rawPacket = buildPacket(dataPacket)

console.log('\n=== ENCRYPTED PACKET (paste into Python) ===')
console.log(bytesToHex(rawPacket))
console.log('\nPacket length:', rawPacket.length)
console.log('Destination:', bytesToHex(recipientDestinationHash))
