// this is a simple echo-server that runs over websocket

import { identityCreate, getDestinationHash, ratchetCreateNew, ratchetGetPublic, decodePacket, buildAnnounce, buildProof, messageDecrypt, parseLxmfMessage, buildLxmfMessage, getMessageId, announceParse, PACKET_ANNOUNCE, PACKET_PROOF, PACKET_DATA } from '../src/index.js'
import { bytesToHex } from '@noble/curves/utils.js'

const uri = 'wss://signal.konsumer.workers.dev/ws/reticulum'

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
  console.log(`ANNOUNCE from ${Buffer.from(packet.destinationHash).toString('hex')}`)
  const announce = announceParse(packet)
  if (announce.valid) {
    announces[Buffer.from(packet.destinationHash).toString('hex')] = announce
    announces[Buffer.from(packet.destinationHash).toString('hex')].destinationHash = packet.destinationHash
    console.log(`  Saved (${Object.keys(announces).length}) announce from ${Buffer.from(packet.destinationHash).toString('hex')}`)
  } else {
    console.log('  Valid: No')
    // console.log(`  Raw Bytes: ${bytesToHex(packet.raw)}`)
    // console.log({
    //   destinationHash: bytesToHex(packet.destinationHash),
    //   sourceHash: bytesToHex(packet.sourceHash),
    //   context: packet.context,
    //   ifacFlag: packet.ifacFlag,
    //   headerType: packet.headerType,
    //   contextFlag: packet.contextFlag,
    //   propagationType: packet.propagationType,
    //   destinationType: packet.destinationType,
    //   packetType: packet.packetType,
    //   hops: packet.hops
    // })
  }
}

// Handle PROOF packets
async function handleProof(packet) {
  console.log(`PROOF for message ${Buffer.from(packet.destinationHash).toString('hex')}`)
  // TODO: verify proof if needed
}

// Handle DATA packets
async function handleData(packet, websocket) {
  const messageId = getMessageId(packet)
  console.log(`DATA (${Buffer.from(messageId).toString('hex')}) for ${Buffer.from(packet.destinationHash).toString('hex')}`)

  // Check if it's for me
  if (Buffer.from(packet.destinationHash).toString('hex') === Buffer.from(meDest).toString('hex')) {
    // Send PROOF
    console.log(`sending PROOF (${Buffer.from(messageId).toString('hex')})`)
    const proofBytes = buildProof(me, packet, messageId)
    websocket.send(proofBytes)

    // Decrypt the message
    const plaintext = messageDecrypt(packet, me, [ratchet])
    if (plaintext) {
      try {
        const message = parseLxmfMessage(plaintext)
        const contentText = new TextDecoder().decode(message.content)
        const senderHash = Buffer.from(message.sourceHash).toString('hex')
        console.log(`  From: ${senderHash}`)
        console.log(`  Title: ${new TextDecoder().decode(message.title)}`)
        console.log(`  Content: ${contentText}`)

        // Echo the message back to sender
        const senderAnnounce = announces[senderHash]
        if (senderAnnounce) {
          console.log(`  Echoing message back to ${senderHash}`)

          websocket.send(
            buildLxmfMessage(me, meDest, ratchet, senderAnnounce, {
              title: 'Echo',
              content: contentText,
              timestamp: Math.floor(Date.now() / 1000)
            })
          )
        } else {
          console.log(`Cannot echo: no announce found for ${senderHash}`)
        }
      } catch (e) {
        console.error('  Error parsing LXMF message:', e)
      }
    } else {
      console.log('  Could not decrypt')
    }
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
console.log(`My destination: ${Buffer.from(meDest).toString('hex')}`)

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
