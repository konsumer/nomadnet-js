// This will announce itself and show announces, from a websoocket
// when it receives an LXMF message it will respond

import { bytesToHex } from '@noble/curves/utils.js'
import { generateIdentity, getLxmfIdentity, pubFromPrivate, unpackReticulum, parseAnnounce, parseLxmf, buildAnnounce, PACKET_ANNOUNCE, PACKET_DATA, DESTINATION_SINGLE } from '../src/index.js'

import WebSocket from 'ws'

const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum', ANNOUNCE_INTERVAL = 30000 } = process.env

const { encPriv, sigPriv } = generateIdentity()
const { encPub, sigPub } = pubFromPrivate({ encPriv, sigPriv })
const self = getLxmfIdentity(pubFromPrivate({ encPub, sigPub }))

const ws = new WebSocket(RETICULUM_WS_URL)

ws.on('error', ({ message }) => {
  console.error('ERROR', message)
})

// periodically announce ourself
async function annouce() {
  const p = await buildAnnounce({ encPriv, sigPriv, appName: 'lxmf', aspects: ['delivery'], peerName: 'test peer' })
  // console.log('Sending', p)
  console.log('ANNOUNCE myself')
  ws.send(p.packet)
}

ws.on('open', () => {
  console.log(`Connected to ${RETICULUM_WS_URL} on LXMF: ${bytesToHex(lxmf.destinationHash)}`)
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
    if (p.destinationType === DESTINATION_SINGLE && bytesToHex(p.destinationHash) === bytesToHex(lxmf.destinationHash)) {
      const lxm = parseLxmf(p, { encPriv, sigPriv })
      console.log(lxm)
    }
  }
})
