// this is a simple echo-server that runs over websocket

// prettier-ignore
import {
  buildAnnounce,
  buildLxmf,
  buildProof,
  getDestinationHash,
  parseAnnounce,
  parseLxmf,
  parsePacket,
  parseProof,
  privateIdentity,
  privateRatchet,
  publicIdentity,
  publicRatchet,
  
  PACKET_ANNOUNCE,
  PACKET_PROOF,
  PACKET_DATA
} from '../src/index.js'
import { bytesToHex, equalBytes } from '../src/utils.js'
import WebSocket from 'ws'

const websocket = new WebSocket('wss://signal.konsumer.workers.dev/ws/reticulum')

// Create identity and destination
const me = privateIdentity()
const mePub = publicIdentity(me)
const meDest = getDestinationHash(mePub)
const ratchet = privateRatchet()
const ratchetPub = publicRatchet(ratchet)

console.log(`Connecting to ${websocket._url}`)

function announceMyself() {
  console.log(`ANNOUNCE me (${bytesToHex(meDest)})`)
  websocket.send(buildAnnounce(me, mePub, ratchetPub))
}

const sentMessages = {}
const announces = {}

const packetTypes = {
  [PACKET_ANNOUNCE]: 'ANNOUNCE',
  [PACKET_DATA]: 'DATA',
  [PACKET_PROOF]: 'PROOF'
}

websocket.on('message', async (data) => {
  try {
    const packet = parsePacket(data)
    console.log(`${packetTypes[packet.packetType]} (${bytesToHex(packet.destinationHash)})`)

    switch (packet.packetType) {
      case PACKET_ANNOUNCE:
        {
          const announce = parseAnnounce(packet)
          console.log('  Valid:', announce.valid)
          if (announce.valid) {
            announces[packet.destinationHash] = { ...packet, ...announce }
          }
        }
        break

      case PACKET_DATA: {
        if (equalBytes(meDest, packet.destinationHash)) {
          const p = parseLxmf(packet, mePub, [ratchet])
          console.log(`  Message ID: ${bytesToHex(packet.packetHash)}`)
          console.log(`  Sending PROOF`)
          websocket.send(buildProof(packet, me))

          if (p) {
            const { sourceHash, title, content } = p
            console.log('  Parse:', JSON.stringify({ from: bytesToHex(sourceHash), title, content }))

            if (announces[packet.destinationHash]) {
              console.log(`  Sending Response`)
              const receiverRatchetPub = announces[packet.destinationHash]?.ratchetPub
              const receiverPubBytes = announces[packet.destinationHash]?.publicKey
              websocket.send(buildLxmf({ sourceHash: meHash, senderPrivBytes: me, receiverPubBytes, receiverRatchetPub, title: 'EchoBot', content }))
            } else {
              console.log(`  Have not received an announce for ${bytesToHex(sourceHash)}`)
            }
          } else {
            console.log('  Parse: No')
          }
        } else {
          console.log(' ', 'Not for me')
        }
        break
      }

      case PACKET_PROOF:
        {
          const fullPacketHash = sentMessages[packet.destinationHash]
          const { valid } = parseProof(packet, mePub, fullPacketHash)
        }

        break
    }
  } catch (e) {
    console.error('Error:', e.message)
  }
})

websocket.on('open', () => {
  console.log('Connected!')
  announceMyself()
  setInterval(announceMyself, 30000)
})

websocket.on('error', (error) => {
  console.error('WebSocket error:', error)
})

websocket.on('close', () => {
  console.log('Disconnected')
  setTimeout(() => main(), 5000)
})
