// Use this as a PipeInterface in nomadnet

import WebSocket, { createWebSocketStream } from 'ws'

const [, , URL = 'ws://0.0.0.0:8080'] = process.argv
const ws = new WebSocket(URL)
const duplex = createWebSocketStream(ws)
duplex.on('error', console.error)
duplex.pipe(process.stdout)
process.stdin.pipe(duplex)
