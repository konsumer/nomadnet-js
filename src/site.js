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
const buttonCopy = document.getElementById('buttonCopy')
const lxmfAddress = document.getElementById('lxmfAddress')
const buttonAnnounce = document.getElementById('buttonAnnounce')
const peerList = document.getElementById('peerList')
const dialogPopupMessage = document.getElementById('dialogPopupMessage')
const inputSendAddress = document.getElementById('inputSendAddress')
const buttonSendMessage = document.getElementById('buttonSendMessage')
const inputSendBody = document.getElementById('inputSendBody')
const inputSendTitle = document.getElementById('inputSendTitle')

const packetTypeNames = {}
packetTypeNames[rns.PACKET_DATA] = 'DATA'
packetTypeNames[rns.PACKET_ANNOUNCE] = 'ANNOUNCE'
packetTypeNames[rns.PACKET_LINKREQUEST] = 'LINKREQUEST'
packetTypeNames[rns.PACKET_PROOF] = 'PROOF'

const decoder = new TextDecoder()

let identity
const messages = {}
const ratchets = []
let ratchetPub
let peers = JSON.parse(localStorage.peers || '{}')

// ANNOUNCE yourself
function announce() {
  if (identity) {
    console.log(`ANNOUNCE (${identity.destinationHex})`)
    if (!ratchetPub) {
      addRatchet()
    }
    ws.send(rns.buildAnnounce(identity.private, identity.public, ratchetPub))
  }
}

// add a new ratchet
function addRatchet() {
  const ratchet = rns.privateRatchet()
  ratchetPub = rns.publicRatchet(ratchet)
  ratchets.push(ratchet)
}

// handle an incoming packet
function handlePacket(data) {
  const packet = rns.parsePacket(new Uint8Array(data))
  const destinationHex = bytesToHex(packet.destinationHash)
  console.log(`${packetTypeNames[packet.packetType] || 'UNKNOWN'} (${destinationHex})`)

  if (packet.packetType === rns.PACKET_ANNOUNCE) {
    const announce = rns.parseAnnounce(packet)
    console.log(`  Valid: ${announce.valid ? 'Yes' : 'No'}`)
    if (announce.valid) {
      peers[destinationHex] = { ...packet, ...announce, destinationHex }
      updatePeers()
    }
  }

  if (packet.packetType === rns.PACKET_DATA) {
    if (destinationHex === identity.destinationHex) {
      const { title, content, sourceHash } = rns.parseLxmf(packet, identity.public, ratchets)
      console.log(`  Message ID: ${bytesToHex(packet.packetHash)}`)
      console.log(`  Sending PROOF`)
      ws.send(rns.buildProof(packet, identity.private))
      let msg = `<strong>From: </strong>${bytesToHex(sourceHash)}`
      if (title) {
        msg += `<br/><strong>Title: </strong>${title}`
      }
      msg += `<br/>${content}`
      customElements.get('pop-notify').notifyHtml(msg)
    }
  }

  if (packet.packetType === rns.PACKET_PROOF) {
    // TODO: verify PROOF
  }
}

// update the UI list of peers
function updatePeers() {
  localStorage.peers = JSON.stringify(peers)
  peerList.innerHTML = ''
  Object.values(peers).forEach((announce) => {
    const li = document.createElement('li')
    li.className = 'mono'
    li.textContent = announce.destinationHex
    if (identity) {
      li.title = `Click to message ${announce.destinationHex}`
      li.className += ' pointer'
      li.onclick = () => {
        inputSendAddress.value = announce.destinationHex
        inputSendBody.value = ''
        inputSendTitle.value = ''
        dialogPopupMessage.showModal()
      }
    }

    peerList.appendChild(li)
  })
}

buttonGenerate.addEventListener('click', (e) => {
  inputPrivateKey.value = bytesToHex(randomBytes(64))
  buttonCopy.classList.remove('hidden')
})

buttonAnnounce.addEventListener('click', announce)

buttonDeletePeers.addEventListener('click', (e) => {
  localStorage.peers = JSON.stringify('{}')
  peers = {}
  updatePeers()
})

buttonSet.addEventListener('click', (e) => {
  if (inputPrivateKey.value?.length !== 128 || /[^0-9a-fA-F]/.test(inputPrivateKey.value)) {
    alert('Please enter or generate a valid private-key.')
  } else {
    identity = {
      private: rns.privateIdentity()
    }
    identity.public = rns.publicIdentity(identity.private)
    identity.destinationHash = rns.getDestinationHash(identity.public)
    identity.destinationHex = bytesToHex(identity.destinationHash)

    privkeyHolder.remove()
    lxmfAddress.value = identity.destinationHex
    lxmfAddress.parentElement.removeAttribute('hidden')
    setInterval(announce, 60000) // announce every minute
    announce()
    // update the click-handlers of peers becayuse now you have an identity
    updatePeers()
  }
})

buttonCopy.addEventListener('click', (e) => {
  navigator.clipboard.writeText(inputPrivateKey.value).then(() => {
    customElements.get('pop-notify').notifyHtml('Private key copied!')
  })
})

buttonSendMessage.addEventListener('click', (e) => {
  const theirAnnounce = peers[inputSendAddress.value]

  if (!theirAnnounce) {
    console.error(`Could not find announce for ${inputSendAddress.value}`)
    return
  }

  const message = {
    sourceHash: identity.destinationHash,
    senderPrivBytes: identity.private,
    receiverPubBytes: new Uint8Array(Object.values(theirAnnounce.publicKey)),
    receiverRatchetPub: new Uint8Array(Object.values(theirAnnounce.ratchetPub)),
    title: inputSendTitle.value,
    content: inputSendBody.value,
    timestamp: Date.now() / 1000
  }
  console.log('send message', message)
  ws.send(rns.buildLxmf(message))
  dialogPopupMessage.close()
  customElements.get('pop-notify').notifyHtml('Message sent.')
})

for (const b of document.querySelectorAll('.closeDialogPopupMessage')) {
  b.addEventListener('click', () => {
    dialogPopupMessage.close()
  })
}

const ws = new WebSocket(WS_URL)
ws.binaryType = 'arraybuffer'
ws.addEventListener('message', (e) => handlePacket(e.data))
ws.addEventListener('error', (e) => console.error(e))
ws.addEventListener('close', (e) => {
  if (ws) {
    setTimeout(connect, 1000)
  }
})

updatePeers()
