import { WebSocket } from 'ws'
import { generateIdentity, buildAnnouncePacket, parsePacket, parseAnnouncePacket, hdlcDecode, hdlcEncode, saveIdentity, parseIdentityBytes, PACKET_ANNOUNCE } from '../src/index.js'
import { readFileSync, writeFileSync, existsSync } from 'fs'

// Configuration
const WEBSOCKET_URL = process.env.RETICULUM_WS_URL || 'wss://signal.konsumer.workers.dev/ws/reticulum'
const APP_NAME = 'AnnounceExample'
const ASPECTS = 'example.announce'
const ANNOUNCE_INTERVAL = 30000 // 30 seconds
const IDENTITY_FILE = './identity.msgpack'

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

// Connect to websocket
const ws = new WebSocket(WEBSOCKET_URL)

// Buffer for incoming data
let receiveBuffer = new Uint8Array(0)

let announceInterval

ws.on('open', () => {
  console.log('Connected to Reticulum network at', WEBSOCKET_URL)

  // Send initial announce
  sendAnnounce()

  // Set up periodic announces
  announceInterval = setInterval(sendAnnounce, ANNOUNCE_INTERVAL)
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

      // Check if it's an announce packet
      if (packet.header.packetType === PACKET_ANNOUNCE) {
        handleAnnounce(decoded)
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
    console.log('  Public Key:', Buffer.from(announce.publicKey).toString('hex'))
    console.log('  App Name:', announce.name)
    console.log('  Aspects:', announce.aspects || '(none)')
    console.log('  Valid:', announce.isValid)
  } catch (err) {
    console.error('Error handling announce:', err.message)
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...')
  if (announceInterval) {
    clearInterval(announceInterval)
  }
  ws.close()
})

console.log(`
Identity loaded/generated. You can:
- Delete ${IDENTITY_FILE} to generate a new identity
- Copy ${IDENTITY_FILE} to use the same identity on another machine
- The identity contains your cryptographic keys for this node
`)
