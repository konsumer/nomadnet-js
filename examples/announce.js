// This will announce itself and show announces, from a websoocket

import { bytesToHex } from '@noble/curves/utils.js'
import { generateIdentity, getLxmfIdentity, unpackHeader, verifyAnnounce, buildAnnounce, PACKET_ANNOUNCE } from '../src/index.js'

import WebSocket from 'ws'

const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum', ANNOUNCE_INTERVAL = 30000 } = process.env

const { encPriv, sigPriv } = generateIdentity()
const lxmf = getLxmfIdentity({ encPriv, sigPriv })

const ws = new WebSocket(RETICULUM_WS_URL)

ws.on('error', ({ message }) => {
  console.error('ERROR', message)
})

// periodically announce ourself
async function annouce() {
  const p = await buildAnnounce({ encPriv, sigPriv, appName: 'lxmf', aspects: ['delivery'], peerName: 'test peer' })
  console.log('Sending announce:', p)
  ws.send(p.packet)
}
setInterval(annouce, ANNOUNCE_INTERVAL)
ws.on('open', () => {
  console.log(`Connected to ${RETICULUM_WS_URL} on LXMF: ${bytesToHex(lxmf.destinationHash)}`)
  annouce()
})

ws.on('message', (data) => {
  const p = unpackHeader(data)
  console.log('Received', p)
  if (p.packetType === PACKET_ANNOUNCE) {
    const a = verifyAnnounce(p)
    console.log('ANNOUNCE', a)
  }
})
