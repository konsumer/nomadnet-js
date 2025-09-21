import WebsocketNativeInterfaceType from '../src/interfaces/WebsocketNativeInterface.js'
import { hex } from '../src/index.js'

// Configuration
const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum' } = process.env
const ANNOUNCE_INTERVAL = 30000 // 30 seconds

const client = new WebsocketNativeInterfaceType()
client.open({ url: RETICULUM_WS_URL })

client.on('error', ({ detail }) => {
  console.error('ERROR', detail)
})

// client.on('message', ({ detail: { raw, reticulum } }) => {
//   console.log('MESSAGE:', message)
//   console.log(hex(raw, ' '))
// })

client.on('announce', async ({ detail: { raw, reticulum, announce } }) => {
  console.log('ANNOUNCE:', { reticulum, announce })
  console.log(hex(raw, ' '))
})
