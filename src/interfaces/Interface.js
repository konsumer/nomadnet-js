import { parseReticulum, PACKET_DATA, PACKET_ANNOUNCE, PACKET_LINKREQ, PACKET_PROOF } from '../index.js'

// This represents a transport-interface
// it emits "error", "open", "close", "message", "announce", "data", "link", "proof" events
export class InterfaceType extends EventTarget {
  on(evname, callback) {
    this.addEventListener(evname, callback)
  }

  off(evname, callback) {
    this.removeEventListener(evname, callback)
  }

  emit(evname, obj = {}) {
    this.dispatchEvent(new CustomEvent(evname, { detail: obj }))
  }

  // parse a binary message and trigger the correct messages
  async parse(data) {
    try {
      const message = await parseReticulum(data)
      this.emit('message', message)
      if (message.reticulum.packetType === PACKET_DATA) {
        this.emit('data', message)
      } else if (message.reticulum.packetType === PACKET_ANNOUNCE) {
        this.emit('announce', message)
      } else if (message.reticulum.packetType === PACKET_LINKREQ) {
        this.emit('link', message)
      } else if (message.reticulum.packetType === PACKET_PROOF) {
        this.emit('proof', message)
      }
    } catch (e) {
      this.emit('error', e)
    }
  }
}
