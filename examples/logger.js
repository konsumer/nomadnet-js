// This will simply output traffic logs on a websocket
// run other clients on the same socket, and you can see their packets
// I used this to build offline-test.

import { bytesToHex } from '@noble/curves/utils.js'
import { packetUnpack, getMessageId, PACKET_DATA, PACKET_ANNOUNCE, PACKET_LINKREQUEST, PACKET_PROOF } from '../src/index.js'

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
  const p = packetUnpack(data)
  let destinationAddress = bytesToHex(p.destinationHash)
  if (p.packetType === PACKET_DATA) {
    console.log(`${packetTypeNames[p.packetType]} (${destinationAddress} - ${bytesToHex(getMessageId(p))}):`, bytesToHex(data))
  } else {
    console.log(`${packetTypeNames[p.packetType] || `UNKNOWN ${p.packetType}`} (${destinationAddress}):`, bytesToHex(data))
  }
})
