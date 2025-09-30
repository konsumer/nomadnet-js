// This will simply output traffic logs on a websocket
// run other clients on the same neetwork, and you can see their packets

import { bytesToHex } from '@noble/curves/utils.js'
import { unpackReticulum, PACKET_DATA, PACKET_ANNOUNCE, PACKET_LINKREQUEST, PACKET_PROOF } from '../src/index.js'

import WebSocket from 'ws'

const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum', ANNOUNCE_INTERVAL = 30000 } = process.env

const ws = new WebSocket(RETICULUM_WS_URL)

ws.on('error', ({ message }) => {
  console.error('ERROR', message)
})

const packetTypeNames = {}
packetTypeNames[PACKET_DATA] = 'DATA'
packetTypeNames[PACKET_ANNOUNCE] = 'ANNOUNCE'
packetTypeNames[PACKET_LINKREQUEST] = 'LINKREQUEST'
packetTypeNames[PACKET_PROOF] = 'PROOF'

ws.on('message', (data) => {
  const p = unpackReticulum(data)
  let destinationAddress = bytesToHex(p.destinationHash)
  console.log(`${packetTypeNames[p.packetType]} (${destinationAddress}): `, bytesToHex(data))
  // console.log(p)
})
