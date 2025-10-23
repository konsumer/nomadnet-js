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

      console.log('\n=== My ANNOUNCE ===')
      console.log(`  Valid: ${parsed.valid}`)
      console.log(`  Destination: ${bytesToHex(parsed.destinationHash)}`)
      console.log(`  Sign pub: ${bytesToHex(parsed.keyPubSignature)}`)
      console.log(`  Encrypt pub: ${bytesToHex(parsed.keyPubEncrypt)}`)
      console.log(`  Ratchet pub: ${bytesToHex(parsed.ratchetPub)}`)

      console.log('\n=== PROOF Verification ===')
      console.log(`  My sign private: ${bytesToHex(me.private.sign).slice(0, 32)}...`)
      console.log(`  My sign public: ${bytesToHex(me.public.sign)}`)

      // In your announce check:
      console.log(`  Announced sign public: ${bytesToHex(parsed.keyPubSignature)}`)
      console.log(`  Match: ${bytesToHex(me.public.sign) === bytesToHex(parsed.keyPubSignature)}`)

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

    console.log(`  Raw Bytes: ${bytesToHex(packet.raw)}`)

    // Decrypt the message
    const plaintext = messageDecrypt(packet, me, [ratchet])

    if (plaintext) {
      console.log(`  Decrypted ${plaintext.length} bytes`)

      // Try without context byte (offset 18)
      const modifiedHeader = new Uint8Array([packet.raw[0] & 0x0f])
      const dataNoContext = packet.raw.slice(18) // Skip header + hops + dest only
      const messageIdNoContext = _sha256(new Uint8Array([...modifiedHeader, ...dataNoContext]))

      console.log(`  Message ID (with context): ${bytesToHex(messageId)}`)
      console.log(`  Message ID (no context): ${bytesToHex(messageIdNoContext)}`)

      websocket.send(buildProof(me, packet, messageId))
      websocket.send(buildProof(me, packet, messageIdNoContext))

      try {
        const message = decodeMessage(plaintext)
        console.log(`  From: ${bytesToHex(message.senderHash)}`)
        console.log(`  Title: ${message.title}`)
        console.log(`  Content: ${message.content}`)

        const senderHashHex = bytesToHex(message.senderHash)
        const recipientAnnounce = announces[senderHashHex]

        // When you receive an announce
        console.log(`  Stored announce: ${senderHashHex}`)
        console.log(`    Destination: ${bytesToHex(recipientAnnounce.destinationHash)}`)
        console.log(`    Encrypt pub: ${bytesToHex(recipientAnnounce.keyPubEncrypt)}`)
        console.log(`    Sign pub: ${bytesToHex(recipientAnnounce.keyPubSignature)}`)

        if (recipientAnnounce) {
          console.log(`  Found announce for ${senderHashHex}`)
          console.log(`  Their dest: ${bytesToHex(recipientAnnounce.destinationHash)}`)
          console.log(`  My dest: ${bytesToHex(meDest)}`)

          const retMessage = buildMessage(me, meDest, recipientAnnounce, {
            title: 'EchoBot',
            content: message.content
          })

          console.log(`  Sending echo (${retMessage.length} bytes)`)
          console.log(`  Echo packet hex (first 100): ${bytesToHex(retMessage.slice(0, 100))}`)

          console.log(`  Reply messageId (32 bytes): ${bytesToHex(getMessageId(decodePacket(retMessage)))}`)
          websocket.send(retMessage)
        } else {
          console.log(`  No announce found for ${senderHashHex}`)
          console.log(`  Available announces: ${Object.keys(announces).join(', ')}`)
        }
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
