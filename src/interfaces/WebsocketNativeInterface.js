// this is a demo "interface" that just connects to a websocket on native node.
// Eventually similar modules could be made for other interfaces, but initially I am just setting these up for websocket in node/browser

import { InterfaceType } from './Interface.js'
import { WebSocket } from 'ws'

export default class WebsocketNativeInterfaceType extends InterfaceType {
  open({ url = 'wss://signal.konsumer.workers.dev/ws/reticulum' }) {
    this.url = url
    this.ws = new WebSocket(url)

    this.ws.on('open', () => {
      this.connected = true
      this.emit('open')
    })

    this.ws.on('error', (err) => {
      this.emit('error', err)
    })

    this.ws.on('close', () => {
      this.connected = false
      this.emit('close')
    })

    this.ws.on('message', (data) => {
      this.parse(data)
    })
  }

  close() {
    this.ws.close()
  }

  send(bytes) {
    this.ws.send(bytes)
  }
}
