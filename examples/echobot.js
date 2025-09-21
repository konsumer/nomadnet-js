import { WebSocket } from 'ws'
import { generateIdentity, buildAnnouncePacket, buildLinkRequestPacket, parsePacket, parseAnnouncePacket, buildLxmfMessage, parseLxmfMessage, hdlcDecode, hdlcEncode, saveIdentity, parseIdentityBytes, getDestinationHash, randomBytes, PACKET_ANNOUNCE, PACKET_LINKREQUEST, PACKET_PROOF, PACKET_DATA, CONTEXT_NONE } from '../src/index.js'
import { readFileSync, writeFileSync, existsSync } from 'fs'

// Configuration
const WEBSOCKET_URL = process.env.RETICULUM_WS_URL || 'wss://signal.konsumer.workers.dev/ws/reticulum'
const APP_NAME = 'EchoBot'
const ASPECTS = 'example.echobot'
const ANNOUNCE_INTERVAL = 30000 // 30 seconds
const IDENTITY_FILE = './echobot-identity.msgpack'

// Load or generate identity
let identity
if (existsSync(IDENTITY_FILE)) {
  console.log('Loading existing identity from', IDENTITY_FILE)
  const identityData = readFileSync(IDENTITY_FILE)
  identity = parseIdentityBytes(identityData)
  console.log('Loaded identity with hash:', Buffer.from(identity.hash).toString('hex'))
} else {
  console.log('Generating new identity')
  identity = generateIdentity()
  console.log('Generated identity with hash:', Buffer.from(identity.hash).toString('hex'))

  // Save the identity for future use
  const identityData = saveIdentity(identity)
  writeFileSync(IDENTITY_FILE, identityData)
  console.log('Saved identity to', IDENTITY_FILE)
}

// Calculate our destination hash
const destinationHash = getDestinationHash(identity, APP_NAME, ASPECTS)
console.log('EchoBot destination hash:', Buffer.from(destinationHash).toString('hex'))

// Track active links and their states
const links = new Map()

// Connect to websocket
const ws = new WebSocket(WEBSOCKET_URL)

// Buffer for incoming data
let receiveBuffer = new Uint8Array(0)

ws.on('open', () => {
  console.log('Connected to Reticulum network at', WEBSOCKET_URL)

  // Send initial announce
  sendAnnounce()

  // Set up periodic announces
  setInterval(sendAnnounce, ANNOUNCE_INTERVAL)
})

ws.on('message', (data) => {
  // Convert to Uint8Array
  const newData = new Uint8Array(data)

  // Append to buffer
  const combined = new Uint8Array(receiveBuffer.length + newData.length)
  combined.set(receiveBuffer)
  combined.set(newData, receiveBuffer.length)
  receiveBuffer = combined

  // Try to decode HDLC frames
  let decoded
  while ((decoded = hdlcDecode(receiveBuffer)) !== null) {
    // Remove the processed frame from buffer
    const frameEnd = receiveBuffer.indexOf(0x7e, receiveBuffer.indexOf(0x7e) + 1) + 1
    receiveBuffer = receiveBuffer.slice(frameEnd)

    try {
      // Parse the packet
      const packet = parsePacket(decoded)

      // Handle different packet types
      switch (packet.header.packetType) {
        case PACKET_ANNOUNCE:
          handleAnnounce(decoded)
          break
        case PACKET_LINKREQUEST:
          handleLinkRequest(packet)
          break
        case PACKET_PROOF:
          handleProof(packet)
          break
        case PACKET_DATA:
          handleData(packet)
          break
      }
    } catch (err) {
      console.error('Error parsing packet:', err.message)
    }
  }
})

ws.on('error', (err) => {
  console.error('WebSocket error:', err)
})

ws.on('close', () => {
  console.log('Connection closed')
  process.exit(0)
})

function sendAnnounce() {
  try {
    const announcePacket = buildAnnouncePacket(identity, APP_NAME, ASPECTS)
    const encoded = hdlcEncode(announcePacket)

    ws.send(encoded)
    console.log(`Sent announce for ${APP_NAME}:${ASPECTS}`)
  } catch (err) {
    console.error('Error sending announce:', err)
  }
}

function handleAnnounce(packetData) {
  try {
    const announce = parseAnnouncePacket(packetData)

    if (!announce.isValid) {
      console.log('Received invalid announce (signature verification failed)')
      return
    }

    console.log('\nReceived ANNOUNCE:')
    console.log('  Destination:', Buffer.from(announce.destination).toString('hex'))
    console.log('  App Name:', announce.name)
    console.log('  Aspects:', announce.aspects || '(none)')
  } catch (err) {
    console.error('Error handling announce:', err.message)
  }
}

function handleLinkRequest(packet) {
  console.log('\nReceived LINK REQUEST')
  console.log('  From:', Buffer.from(packet.source || new Uint8Array()).toString('hex'))
  console.log('  To:', Buffer.from(packet.destination).toString('hex'))

  // Check if the link request is for us
  const isForUs = packet.destination.every((byte, i) => byte === destinationHash[i])

  if (isForUs) {
    console.log('  Link request is for us!')

    // Extract the requester's public key and link ID from the payload
    if (packet.payload.length >= 32) {
      const requesterPublicKey = packet.payload.slice(0, 32)
      const linkId = packet.payload.slice(32, 48) // 16 byte link ID

      // Store link information
      const linkIdHex = Buffer.from(linkId).toString('hex')
      links.set(linkIdHex, {
        publicKey: requesterPublicKey,
        linkId: linkId,
        established: false,
        remoteIdentity: packet.source
      })

      console.log('  Stored link info for ID:', linkIdHex)

      // TODO: In a real implementation, we would:
      // 1. Generate a link proof packet
      // 2. Establish the encrypted channel
      // 3. Send the proof back
      console.log('  (Link establishment not fully implemented)')
    }
  }
}

function handleProof(packet) {
  console.log('\nReceived PROOF packet')
  console.log('  Destination:', Buffer.from(packet.destination).toString('hex'))

  // TODO: Verify the proof and complete link establishment
  console.log('  (Proof handling not implemented)')
}

function handleData(packet) {
  console.log('\nReceived DATA packet')
  console.log('  Destination:', Buffer.from(packet.destination).toString('hex'))
  console.log('  Context:', packet.context)
  console.log('  Payload size:', packet.payload.length)

  // Check if it's an LXMF message
  if (packet.context === CONTEXT_NONE || packet.context === 0x00) {
    try {
      // Try to parse as LXMF message
      const message = parseLxmfMessage(packet.payload)

      console.log('\nReceived LXMF Message:')
      console.log('  From:', Buffer.from(message.source).toString('hex'))
      console.log('  Timestamp:', new Date(message.timestamp * 1000).toISOString())
      console.log('  Title:', message.title || '(no title)')
      console.log('  Content:', message.content || '(no content)')
      console.log('  Fields:', message.fields || {})

      // Echo the message back
      if (message.content) {
        console.log('\nEchoing message back...')
        const echoMessage = buildLxmfMessage(
          identity,
          message.source, // Send back to sender
          `Echo: ${message.content}`,
          'Echo Reply',
          {
            original_timestamp: message.timestamp,
            echo_time: Date.now() / 1000
          }
        )

        // TODO: In a real implementation, we would:
        // 1. Package this LXMF message into a Reticulum packet
        // 2. Send it through the established link or via transport
        console.log('  (Message sending not fully implemented)')
        console.log('  Would echo:', echoMessage.content)
      }
    } catch (err) {
      console.log('  Not an LXMF message or parsing failed:', err.message)
    }
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...')
  ws.close()
})

console.log(`
EchoBot Started!
================
Identity: ${Buffer.from(identity.hash).toString('hex')}
Destination: ${Buffer.from(destinationHash).toString('hex')}
App Name: ${APP_NAME}
Aspects: ${ASPECTS}

The bot will:
- Send announce packets every ${ANNOUNCE_INTERVAL / 1000} seconds
- Accept link requests
- Echo back any LXMF messages received

Note: Link establishment and message sending are partially implemented.
In a complete implementation, you would need to handle:
- Full link establishment with proof packets
- Encryption key derivation for links
- Proper LXMF message routing
- Message delivery receipts
`)
