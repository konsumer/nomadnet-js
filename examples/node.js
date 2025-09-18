#!/usr/bin/env node

// Create a new LXMF ID, and announce myself once as a node

import { generateIdentity, createAnnouncement, hdlcFrame, destinationHash, bytesToHex } from '../src/index.js'
import WebSocket from 'ws'

const WEBSOCKET_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum'

const identity = await generateIdentity()
const displayName = `Node ${identity.hexhash.slice(0, 8)}`

// Calculate NomadNetwork node address
const nodeAddr = await destinationHash(identity, 'nomadnetwork', 'node')
const nodeAddrHex = bytesToHex(nodeAddr)

console.log(`Identity (${displayName}) : <${identity.hexhash}>`)
console.log(`Node Addr                : <${nodeAddrHex}>`)

const ws = new WebSocket(WEBSOCKET_URL)

ws.on('open', async () => {
  const frame = hdlcFrame(await createAnnouncement(identity, 'nomadnetwork', ['node'], displayName))
  console.log('Sending peer announcement')
  await ws.send(frame)
  ws.close()
})
