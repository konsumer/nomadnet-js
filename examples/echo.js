// this is a simple echo-server that runs over websocket

import { _sha256, identityCreate, getDestinationHash, ratchetCreateNew, ratchetGetPublic, decodePacket, buildAnnounce, proofValidate, buildProof, decodeMessage, buildMessage, messageDecrypt, getMessageId, announceParse, PACKET_ANNOUNCE, PACKET_PROOF, PACKET_DATA } from '../src/index.js'
import { bytesToHex } from '@noble/curves/utils.js'

const uri = 'wss://signal.konsumer.workers.dev/ws/reticulum'

const decoder = new TextDecoder()
const encoder = new TextEncoder()

// Create identity and destination
const me = identityCreate()
const meDest = getDestinationHash(me, 'lxmf', 'delivery')

// Create ratchet (normally regenerated periodically)
const ratchet = ratchetCreateNew()
const ratchetPub = ratchetGetPublic(ratchet)

// Track announces from other nodes
const announces = {}

// Periodic announce function
async function periodicAnnounce(websocket, interval = 30000) {
  while (true) {
    try {
      const announceBytes = buildAnnounce(me, meDest, 'lxmf.delivery', ratchetPub)
      const decoded = decodePacket(announceBytes)
      const parsed = announceParse({ destinationHash: meDest, ...decoded })
      websocket.send(announceBytes)
      await new Promise((resolve) => setTimeout(resolve, interval))
    } catch (e) {
      console.error('Announce error:', e)
      break
    }
  }
}

// Handle ANNOUNCE packets
async function handleAnnounce(packet) {
  console.log(`ANNOUNCE from ${bytesToHex(packet.destinationHash)}`)
  const announce = announceParse(packet)
  if (announce.valid) {
    announces[bytesToHex(packet.destinationHash)] = announce
    announces[bytesToHex(packet.destinationHash)].destinationHash = packet.destinationHash
    console.log(`  Saved (${Object.keys(announces).length}) announce from ${bytesToHex(packet.destinationHash)}`)
  } else {
    console.log('  Valid: No')
  }
}

// Handle PROOF packets
async function handleProof(packet) {
  console.log(`PROOF for message ${bytesToHex(packet.destinationHash)}`)
  const valid = proofValidate(packet)
  console.log(`  Valid: ${valid ? 'Yes' : 'No'}`)
}

// Handle DATA packets
async function handleData(packet, websocket) {
  const messageId = getMessageId(packet)
  console.log(`\nDATA (${bytesToHex(messageId)}) for ${bytesToHex(packet.destinationHash)}`)

  // Check if it's for me
  if (bytesToHex(packet.destinationHash) === bytesToHex(meDest)) {
    console.log('  Message is for ME')
    console.log(`  Message ID: ${bytesToHex(messageId)}`)

    // console.log(`  Raw Bytes: ${bytesToHex(packet.raw)}`)

    // Decrypt the message
    const plaintext = messageDecrypt(packet, me, [ratchet])

    if (plaintext) {
      console.log(`  Decrypted ${plaintext.length} bytes`)

      const proofPacket = buildProof(me, packet, messageId)
      console.log(`[JS_SEND] Sending PROOF`)
      console.log(`[JS_SEND] PROOF hex: ${bytesToHex(proofPacket)}`)
      websocket.send(proofPacket)

      try {
        const message = decodeMessage(plaintext)
        const senderHashHex = bytesToHex(message.senderHash)
        const recipientAnnounce = announces[senderHashHex]
      } catch (e) {
        console.error('  Error parsing LXMF message:', e)
        console.error(e.stack)
      }
    } else {
      console.log('  Could not decrypt')
    }
  } else {
    console.log(`  Not for me (mine: ${bytesToHex(meDest)})`)
  }
}

// Handle incoming messages
async function handleIncoming(websocket) {
  websocket.on('message', async (data) => {
    try {
      const packet = decodePacket(new Uint8Array(data))
      if (packet.packetType === PACKET_ANNOUNCE) {
        await handleAnnounce(packet)
      } else if (packet.packetType === PACKET_PROOF) {
        await handleProof(packet)
      } else if (packet.packetType === PACKET_DATA) {
        console.log(`[JS_RECV] Full packet hex: ${bytesToHex(data)}`)
        const messageId = getMessageId(packet)
        console.log(`[JS_RECV] Calculated message ID: ${bytesToHex(messageId)}`)
        console.log(`[JS_RECV] PROOF destination: ${bytesToHex(messageId.slice(0, 16))}`)

        await handleData(packet, websocket)
      }
    } catch (e) {
      console.error('Error handling packet:', e)
      console.error(e.stack)
    }
  })
}

console.log(`Connecting to ${uri}`)
console.log(`My destination: ${bytesToHex(meDest)}`)

const WebSocket = (await import('ws')).default
const websocket = new WebSocket(uri)

websocket.on('open', () => {
  console.log('Connected!')
  periodicAnnounce(websocket, 30000)
  handleIncoming(websocket)
})

websocket.on('error', (error) => {
  console.error('WebSocket error:', error)
})

websocket.on('close', () => {
  console.log('Disconnected')
  setTimeout(() => main(), 5000)
})
