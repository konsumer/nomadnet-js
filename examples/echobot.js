// This will announce itself and show announces, from a websoocket
// when it receives an LXMF message it will respond

import { bytesToHex } from '@noble/curves/utils.js'
import { generateIdentity, getLxmfIdentity, pubFromPrivate, unpackReticulum, parseAnnounce, buildAnnounce, generateRatchetKeypair, PACKET_ANNOUNCE, PACKET_DATA, DESTINATION_SINGLE } from '../src/index.js'

import WebSocket from 'ws'

const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum', ANNOUNCE_INTERVAL = 30000 } = process.env

const { encPriv, sigPriv } = generateIdentity()
const { encPub, sigPub } = pubFromPrivate({ encPriv, sigPriv })
const { destinationHash, identityHash } = getLxmfIdentity({ encPub, sigPub })
const destinationHex = bytesToHex(destinationHash)

// in a normal application this would be stored & rotated
let { ratchetPriv, ratchetPub } = generateRatchetKeypair()

const ws = new WebSocket(RETICULUM_WS_URL)

ws.on('error', ({ message }) => {
  console.error('ERROR', message)
})

// periodically announce ourself
async function annouce() {
  const p = await buildAnnounce({ encPriv, sigPriv, appName: 'lxmf', aspects: ['delivery'], peerName: 'test peer', ratchet: ratchetPub, transportType: 2, destinationType: 0, data: 0 })
  // console.log('Sending', p)
  console.log('ANNOUNCE myself')
  ws.send(p.packet)
}

ws.on('open', () => {
  console.log(`Connected to ${RETICULUM_WS_URL} on LXMF: ${destinationHex}`)
  annouce()
  setInterval(annouce, ANNOUNCE_INTERVAL)
})

ws.on('message', (data) => {
  const p = unpackReticulum(data)

  // console.log('Received', p)
  if (p.packetType === PACKET_ANNOUNCE) {
    const a = parseAnnounce(p)
    console.log('ANNOUNCE from', bytesToHex(p.destinationHash))
  }

  if (p.packetType === PACKET_DATA) {
    if (p.destinationType === DESTINATION_SINGLE && bytesToHex(p.destinationHash) === destinationHex) {
      console.log('message to me', p)
      // TODO: read this message
      // TODO: respond to this message with same text
    }
  }
})
