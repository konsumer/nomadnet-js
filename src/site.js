// This is for the browser-demo

import 'pop-notify'
import './site.css'

import * as rns from '../src/index.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/curves/utils.js'

const WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum'

const privkeyHolder = document.getElementById('privkeyHolder')
const inputPrivateKey = document.getElementById('inputPrivateKey')
const buttonGenerate = document.getElementById('buttonGenerate')
const buttonSet = document.getElementById('buttonSet')
const buttonDeletePeers = document.getElementById('buttonDeletePeers')
const lxmfAddress = document.getElementById('lxmfAddress')
const buttonAnnounce = document.getElementById('buttonAnnounce')
const peerList = document.getElementById('peerList')

const packetTypeNames = {}
packetTypeNames[rns.PACKET_DATA] = 'DATA'
packetTypeNames[rns.PACKET_ANNOUNCE] = 'ANNOUNCE'
packetTypeNames[rns.PACKET_LINKREQUEST] = 'LINKREQUEST'
packetTypeNames[rns.PACKET_PROOF] = 'PROOF'

const decoder = new TextDecoder()

// ANNOUNCE yourself
function announce() {
  if (identity) {
    console.log(`ANNOUNCE (${identity.destinationHex})`)
    if (!ratchetPub) {
      addRatchet()
    }
    ws.send(rns.buildAnnounce(identity, identity.destinationHash, 'lxmf.delivery', ratchetPub))
  }
}

// add a new ratchet
function addRatchet() {
  const ratchet = rns.ratchetCreateNew()
  ratchetPub = rns.ratchetGetPublic(ratchet)
  ratchets.push(ratchet)
}

// handle an incoming packet
function handlePacket(data) {
  const packet = rns.decodePacket(new Uint8Array(data))
  const destinationHex = bytesToHex(packet.destinationHash)
  console.log(`${packetTypeNames[packet.packetType] || 'UNKNOWN'} (${destinationHex})`)

  if (packet.packetType === rns.PACKET_ANNOUNCE) {
    const announce = rns.announceParse(packet)
    console.log(`  Valid: ${announce.valid ? 'Yes' : 'No'}`)
    if (announce.valid) {
      peers[destinationHex] = { ...packet, ...announce, destinationHex }
      updatePeers()
    }
  }

  if (packet.packetType === rns.PACKET_DATA) {
    if (destinationHex === identity.destinationHex) {
      const messageId = rns.getMessageId(packet)
      console.log(`sending PROOF (${bytesToHex(messageId)})`)
      ws.send(rns.buildProof(identity, packet, messageId))
      const message = rns.parseLxmfMessage(rns.messageDecrypt(packet, identity, ratchets))
      message.sourceHex = bytesToHex(message.sourceHash)
      const title = decoder.decode(message.title)
      const content = decoder.decode(message.content)

      customElements.get('pop-notify').notifyHtml(title.trim() === '' ? `<strong>${message.sourceHex}</strong><br/>${content}` : `<strong>${message.sourceHex}</strong><br/><strong>${title}</strong><br/>${content}`)

      console.log({ ...message, title, content, timestamp: new Date(message.timestamp * 1000) })
    }
  }

  if (packet.packetType === rns.PACKET_PROOF) {
  }
}

let ws
function connect() {
  ws = new WebSocket(WS_URL)
  ws.binaryType = 'arraybuffer'
  ws.addEventListener('message', (e) => handlePacket(e.data))
  ws.addEventListener('error', (e) => console.error(e))
  ws.addEventListener('close', (e) => {
    if (ws) {
      setTimeout(connect, 1000)
    }
  })
}
connect()

let identity
const messages = {}
const ratchets = []
let ratchetPub
let peers = JSON.parse(localStorage.peers || '{}')
updatePeers()

function updatePeers() {
  localStorage.peers = JSON.stringify(peers)
  peerList.innerHTML = ''
  Object.values(peers).forEach((announce) => {
    const li = document.createElement('li')
    li.className = 'mono'
    li.textContent = announce.destinationHex
    peerList.appendChild(li)
  })
}

buttonGenerate.addEventListener('click', (e) => {
  inputPrivateKey.value = bytesToHex(randomBytes(64))
})

buttonAnnounce.addEventListener('click', announce)

buttonSet.addEventListener('click', (e) => {
  if (inputPrivateKey.value?.length !== 128 || /[^0-9a-fA-F]/.test(inputPrivateKey.value)) {
    alert('Please enter or generate a valid private-key.')
  } else {
    identity = rns.getIdentityFromBytes(hexToBytes(inputPrivateKey.value))
    identity.destinationHash = rns.getDestinationHash(identity, 'lxmf', 'delivery')
    identity.destinationHex = bytesToHex(identity.destinationHash)
    privkeyHolder.remove()
    lxmfAddress.value = identity.destinationHex
    lxmfAddress.parentElement.removeAttribute('hidden')
    // setInterval(announce, 60000 * 60) // announce every hour
    announce()
  }
})

buttonDeletePeers.addEventListener('click', (e) => {
  localStorage.peers = JSON.stringify('{}')
  peers = {}
  updatePeers()
})
