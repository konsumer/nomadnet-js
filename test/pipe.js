import WebSocket from 'ws'
import { appendFile } from 'node:fs/promises'

const [, , URL = 'ws://0.0.0.0:8080', FILENAME] = process.argv

const bufferToHex = (buffer) =>
  Array.from(buffer)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join(' ')
    .toUpperCase()

const ws = new WebSocket(URL)
ws.on('error', console.error)

ws.on('open', () => {
  process.stdin.on('data', async (data) => {
    ws.send(data)
    if (FILENAME) {
      await appendFile(FILENAME, 'S ' + bufferToHex(data) + '\n')
    }
  })
})

ws.on('message', async (data) => {
  process.stdout.write(data)
  if (FILENAME) {
    await appendFile(FILENAME, 'R ' + bufferToHex(data) + '\n')
  }
})

// stream works like this:
// const duplex = WebSocket.createWebSocketStream(ws)
// duplex.on('error', console.error)
// duplex.pipe(process.stdout)
// process.stdin.pipe(duplex)
