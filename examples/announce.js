import h from 'hexy'
import WebsocketNativeInterfaceType from '../src/interfaces/WebsocketNativeInterface.js'

const { hexy } = h

// Configuration
const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum' } = process.env
const APP_NAME = 'AnnounceExample'
const ASPECTS = 'example.announce'
const ANNOUNCE_INTERVAL = 30000 // 30 seconds

const client = new WebsocketNativeInterfaceType()
client.open({ url: RETICULUM_WS_URL })

client.on('error', ({ detail }) => {
  console.error('ERROR', detail)
})

// client.on('message', ({ detail: { raw, reticulum } }) => {
//   console.log('MESSAGE:', message)
//   console.log(hexy.hexy(raw, { numbering: 'none', format: 'twos', caps: 'upper' }))
// })

client.on('announce', ({ detail: { raw, reticulum, announce } }) => {
  console.log('ANNOUNCE:', { reticulum, announce })
  console.log(hexy(raw, { numbering: 'none', format: 'twos', caps: 'upper' }))
})
