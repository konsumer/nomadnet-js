#!/usr/bin/env node

// Create a new LXMF ID, and announce myself once as a peer

import { generateIdentity, createAnnouncement, hdlcFrame } from '../index.js'
import WebSocket from 'ws'

const WEBSOCKET_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum'

const identity = await generateIdentity()
const displayName = `Peer ${identity.hexhash.slice(0, 8)}`

console.log(`Identity (${displayName}): ${identity.hexhash}`)

const ws = new WebSocket(WEBSOCKET_URL)

ws.on('open', async () => {
  const frame = hdlcFrame(await createAnnouncement(identity, 'lxmf', ['delivery'], displayName))
  console.log('Sending peer announcement')
  await ws.send(frame)
  ws.close()
})

