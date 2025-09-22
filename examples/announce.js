import WebsocketNativeInterfaceType from '../src/interfaces/WebsocketNativeInterface.js'
import { hex, createAnnounce } from '../src/index.js'
import { SenderIdentity } from '../src/identity.js'

// Configuration
const { RETICULUM_WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum', ANNOUNCE_INTERVAL = 30000 } = process.env

const sender = await SenderIdentity.generate('chat')

const client = new WebsocketNativeInterfaceType()
client.open({ url: RETICULUM_WS_URL })

client.on('error', ({ detail }) => {
  console.error('ERROR', detail)
})

async function annouce() {
  const p = await createAnnounce(sender)
  console.log('Sending announce:', hex(p, ' '))
  client.send(p)
}

setInterval(annouce, ANNOUNCE_INTERVAL)

client.on('open', () => {
  annouce()
})

// handle incoming announces
client.on('announce', async ({ detail: { raw, reticulum, announce } }) => {
  console.log('ANNOUNCE:', { reticulum, announce })
  console.log(hex(raw, ' '))
})
