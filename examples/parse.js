#!/usr/bin/env node

// Listen for packets and parse them to extract announcements and messages

import { generateIdentity, parsePacket, isMessageForIdentity, extractHdlcFrames, bytesToHex, prettyHash, hdlcFrame, createAnnouncement } from '../src/index.js'
import WebSocket from 'ws'

const WEBSOCKET_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum'

// Generate our identity
const identity = await generateIdentity()
const displayName = `Peer ${identity.hexhash.slice(0, 8)}`

console.log(`Our identity (${displayName}): ${identity.hexhash}`)
console.log('Listening for packets...\n')

// Track seen peers
const peers = new Map()

const ws = new WebSocket(WEBSOCKET_URL)

ws.on('message', async (data) => {
  // Convert to Uint8Array if needed
  const buffer = new Uint8Array(data)

  // Extract HDLC frames
  const frames = extractHdlcFrames(buffer)

  for (const frame of frames) {
    const parsed = await parsePacket(frame)

    switch (parsed.type) {
      case 'announce':
        console.log('📢 Announcement received:')
        console.log(`  Address: ${parsed.address}`)
        console.log(`  Display Name: ${parsed.displayName || '(none)'}`)
        console.log(`  Timestamp: ${new Date(parsed.timestamp * 1000).toISOString()}`)
        console.log(`  Dest Hash: ${prettyHash(parsed.destHash)}`)

        // Store peer info for later messaging
        peers.set(parsed.address, {
          publicKey: parsed.publicKey,
          encPublic: parsed.encPublic,
          sigPublic: parsed.sigPublic,
          displayName: parsed.displayName,
          lastSeen: parsed.timestamp
        })
        console.log(`  ✅ Peer stored (${peers.size} total peers)\n`)
        break

      case 'message':
        // Check if message is for us (example for LXMF delivery)
        const isForUs = await isMessageForIdentity(parsed, identity, 'lxmf', ['delivery'])

        console.log('💬 Message received:')
        console.log(`  Dest Hash: ${prettyHash(parsed.destHash)}`)
        console.log(`  For us: ${isForUs ? '✅ YES' : '❌ NO'}`)
        console.log(`  Data length: ${parsed.messageData.length} bytes`)

        if (isForUs) {
          console.log('  🔐 Message is encrypted for our identity')
          // Here you would decrypt the message using the identity's private key
          // This would be the next step in your implementation
        }
        console.log()
        break

      case 'linkrequest':
        console.log('🔗 Link request received')
        console.log(`  Dest Hash: ${prettyHash(parsed.destHash)}`)
        console.log(`  Data length: ${parsed.linkData.length} bytes\n`)
        break

      case 'proof':
        console.log('✓ Proof packet received')
        console.log(`  Dest Hash: ${prettyHash(parsed.destHash)}`)
        console.log(`  Data length: ${parsed.proofData.length} bytes\n`)
        break

      case 'invalid':
        console.log(`⚠️ Invalid packet: ${parsed.error}\n`)
        break

      default:
        console.log(`❓ Unknown packet type: ${parsed.packetType}`)
        console.log(`  Dest Hash: ${prettyHash(parsed.destHash)}\n`)
    }
  }
})

ws.on('open', async () => {
  console.log('Connected to Reticulum network\n')
  // send an announcement so test-clients can message us
  const frame = hdlcFrame(await createAnnouncement(identity, 'lxmf', ['delivery'], displayName))
  console.log('Sending peer announcement')
  await ws.send(frame)
})

ws.on('close', () => {
  console.log('\nDisconnected from Reticulum network')
  console.log(`Final peer count: ${peers.size}`)

  if (peers.size > 0) {
    console.log('\nDiscovered peers:')
    for (const [address, peer] of peers) {
      console.log(`  - ${peer.displayName || 'Unknown'} <${address}>`)
    }
  }
})

ws.on('error', (error) => {
  console.error('WebSocket error:', error)
})

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...')
  ws.close()
  process.exit(0)
})
