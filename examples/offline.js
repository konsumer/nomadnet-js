// manually offline parsing real traffic (between 2 official clients) using real keys

// demo/demo.js
import * as rns from '../src/index.js'
import { keys, packets, ratchets } from './demo_data.js'
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js'

function arraysEqual(a, b) {
  if (!a || !b) return false
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

console.log('Reticulum Packet Parser Demo\n')

// Verify I get correct destination addresses
const clientA = rns.getIdentityFromBytes(keys['072ec44973a8dee8e28d230fb4af8fe4'])
const clientA_addr = rns.getDestinationHash(clientA, 'lxmf', 'delivery')
console.log(`Client A: ${bytesToHex(clientA_addr)}`)

const clientB = rns.getIdentityFromBytes(keys['76a93cda889a8c0a88451e02d53fd8b9'])
const clientB_addr = rns.getDestinationHash(clientB, 'lxmf', 'delivery')
console.log(`Client B: ${bytesToHex(clientB_addr)}`)

// Put the addresses in easier-to-use shape
const recipients = {
  [bytesToHex(clientA_addr)]: clientA,
  [bytesToHex(clientB_addr)]: clientB
}

// Track DATA packets that have been sent
const sentPackets = {}

for (const packetBytes of packets) {
  console.log('')
  const packet = rns.decodePacket(packetBytes)

  // Validate ANNOUNCE
  if (packet.packetType === rns.PACKET_ANNOUNCE) {
    console.log(`ANNOUNCE to ${bytesToHex(packet.destinationHash)}`)
    const announce = rns.announceParse(packet)
    if (announce.valid) {
      console.log('  Valid: Yes')
    } else {
      console.log('  Valid: No')
    }
  }

  // Decrypt DATA
  if (packet.packetType === rns.PACKET_DATA) {
    console.log(`DATA to ${bytesToHex(packet.destinationHash)}`)

    const packetHashFull = rns.getMessageId(packet) // 32-byte for validation
    const packetHashTruncated = packetHashFull.slice(0, 16) // 16-byte for lookup
    sentPackets[bytesToHex(packetHashTruncated)] = {
      destinationHash: packet.destinationHash,
      fullHash: packetHashFull
    }
    console.log(`  MessageId: ${bytesToHex(packetHashTruncated)}`)

    const destHashHex = bytesToHex(packet.destinationHash)
    const recipient = recipients[destHashHex]

    if (recipient) {
      const decryptedBytes = rns.messageDecrypt(packet, recipient, ratchets)
      if (decryptedBytes) {
        const lxmfMessage = rns.parseLxmfMessage(decryptedBytes)
        console.log(`  Time: ${lxmfMessage.timestamp}`)
        console.log(`  Title: ${new TextDecoder().decode(lxmfMessage.title)}`)
        console.log(`  Content: ${new TextDecoder().decode(lxmfMessage.content)}`)
      } else {
        console.log('  Decryption failed')
      }
    } else {
      console.log('  Unknown recipient')
    }
  }

  // Validate PROOF
  if (packet.packetType === rns.PACKET_PROOF) {
    console.log(`PROOF for ${bytesToHex(packet.destinationHash)}`)
    const destHashHex = bytesToHex(packet.destinationHash)

    if (sentPackets[destHashHex]) {
      const { destinationHash: recipientHash, fullHash: fullPacketHash } = sentPackets[destHashHex]
      const recipientHashHex = bytesToHex(recipientHash)
      const identity = recipients[recipientHashHex]

      if (identity) {
        if (rns.proofValidate(packet, identity, fullPacketHash)) {
          console.log('  Valid: Yes')
        } else {
          console.log('  Valid: No')
        }
      } else {
        console.log('  Unknown identity')
      }
    } else {
      console.log(`  No Message: ${destHashHex}`)
    }
  }
}
