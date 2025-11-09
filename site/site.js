// This is for the browser-demo

import 'pop-notify'
import './site.css'

import { private_identity, public_identity, private_ratchet, public_ratchet, packet_unpack, build_announce, build_data, build_proof, validate_announce, validate_proof, message_decrypt, lxmf_parse, lxmf_build, get_identity_destination_hash, PACKET_DATA, PACKET_ANNOUNCE, PACKET_PROOF, bytesToHex, hexToBytes } from '../src/index.js'

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

const packet_names = {
  [PACKET_DATA]: 'DATA',
  [PACKET_ANNOUNCE]: 'ANNOUNCE',
  [PACKET_PROOF]: 'PROOF'
}

const decoder = new TextDecoder()

let ws
let identity = null
let ratchet_priv = null
let ratchet_pub = null
let peers = JSON.parse(localStorage.peers || '{}')
let sent_messages = new Map()

// Convert Uint8Array to hex string
function toHex(bytes) {
  return bytesToHex(bytes)
}

// Convert hex string to Uint8Array
function fromHex(hex) {
  return hexToBytes(hex)
}

// ANNOUNCE yourself
function announce() {
  if (identity && ws && ws.readyState === WebSocket.OPEN) {
    console.log(`ANNOUNCE ${toHex(identity.destination_hash)}`)
    const pkt = build_announce(identity.private, identity.public, identity.destination_hash, ratchet_priv, ratchet_pub)
    ws.send(pkt)
  }
}

// Handle incoming packets
async function handlePacket(packet_bytes) {
  const packet = packet_unpack(new Uint8Array(packet_bytes))
  const destinationHex = toHex(packet.destination_hash)
  console.log(`${packet_names[packet.packet_type] || 'UNKNOWN'} (${destinationHex})`)

  try {
    if (packet.packet_type === PACKET_ANNOUNCE) {
      const announce = validate_announce(packet)
      if (!announce) {
        console.log('  Valid: False')
        return
      }
      console.log('  Valid: True')
      peers[destinationHex] = announce
      updatePeers()
    }

    if (packet.packet_type === PACKET_DATA) {
      if (!identity) return

      const me_dest_hex = toHex(identity.destination_hash)
      const dest_hex = toHex(packet.destination_hash)

      if (dest_hex === me_dest_hex) {
        const data = await message_decrypt(packet, identity.public, [ratchet_priv])
        if (!data) {
          console.log('  Could not decrypt')
          return
        }

        // Parse LXMF message - need sender's announce for public key
        const source_hash = data.slice(0, 16)
        const source_hash_hex = toHex(source_hash)
        console.log(`  Looking for sender: ${source_hash_hex}`)
        console.log(`  Known peers:`, Object.keys(peers))
        const sender_announce = peers[source_hash_hex]

        if (!sender_announce) {
          console.log('  Unknown sender - need to receive their ANNOUNCE first')
          return
        }

        // Convert public_key from localStorage object to Uint8Array
        const sender_public_key = sender_announce.public_key instanceof Uint8Array ? sender_announce.public_key : new Uint8Array(Object.values(sender_announce.public_key))

        const lxmf = lxmf_parse(data, identity.destination_hash, sender_public_key)
        if (!lxmf || !lxmf.valid) {
          console.log('  Invalid LXMF message')
          return
        }

        const content_text = lxmf.content?.length ? decoder.decode(lxmf.content) : '(no content)'
        const title_text = lxmf.title?.length ? decoder.decode(lxmf.title) : '(no title)'

        console.log(`  From: ${source_hash_hex.slice(0, 16)}...`)
        console.log(`  Title: ${title_text}`)
        console.log(`  Content: ${content_text}`)

        // Send PROOF back
        ws.send(build_proof(packet.raw, identity.private))

        // Show notification
        let msg = `<strong>From: </strong>${source_hash_hex.slice(0, 16)}...`
        if (lxmf.title?.length) {
          msg += `<br/><strong>Title: </strong>${title_text}`
        }
        msg += `<br/>${content_text}`
        customElements.get('pop-notify').notifyHtml(msg)
      }
    }

    if (packet.packet_type === PACKET_PROOF) {
      // Validate PROOF against our sent messages
      const truncated_msg_id = toHex(packet.destination_hash)

      let msg_to_delete = null

      for (const [msg_hash, msg_info] of sent_messages.entries()) {
        if (msg_hash.startsWith(truncated_msg_id)) {
          // Convert hex hash back to Uint8Array
          const full_hash = fromHex(msg_hash)
          const is_valid = validate_proof(packet, msg_info.sender_pub, full_hash)
          if (is_valid) {
            console.log('  Valid PROOF received')
            msg_to_delete = msg_hash
          }
          break
        }
      }

      if (msg_to_delete) {
        sent_messages.delete(msg_to_delete)
      }
    }
  } catch (e) {
    console.log(`  Error: ${e.message}`)
  }
}

// Update the UI list of peers
function updatePeers() {
  localStorage.peers = JSON.stringify(peers)
  peerList.innerHTML = ''
  Object.entries(peers).forEach(([destinationHex, announce]) => {
    const li = document.createElement('li')
    li.className = 'mono'
    li.textContent = destinationHex
    if (identity) {
      li.title = `Click to message ${destinationHex}`
      li.className += ' pointer'
      li.onclick = () => {
        inputSendAddress.value = destinationHex
        inputSendBody.value = ''
        inputSendTitle.value = ''
        dialogPopupMessage.showModal()
      }
    }
    peerList.appendChild(li)
  })
}

// Generate random private key
buttonGenerate.addEventListener('click', () => {
  const priv = private_identity()
  inputPrivateKey.value = toHex(priv)
  buttonCopy.classList.remove('hidden')
})

buttonAnnounce.addEventListener('click', announce)

buttonDeletePeers.addEventListener('click', () => {
  localStorage.peers = '{}'
  peers = {}
  updatePeers()
})

// Set identity and connect
buttonSet.addEventListener('click', () => {
  if (inputPrivateKey.value?.length !== 128 || /[^0-9a-fA-F]/.test(inputPrivateKey.value)) {
    alert('Please enter or generate a valid private-key.')
  } else {
    const priv = fromHex(inputPrivateKey.value)
    const pub = public_identity(priv)
    const dest = get_identity_destination_hash(pub)

    identity = {
      private: priv,
      public: pub,
      destination_hash: dest
    }

    ratchet_priv = private_ratchet()
    ratchet_pub = public_ratchet(ratchet_priv)

    privkeyHolder.remove()
    lxmfAddress.value = toHex(dest)
    lxmfAddress.parentElement.removeAttribute('hidden')

    // Announce periodically
    setInterval(announce, 60000)
    announce()

    // Update the click-handlers of peers because now you have an identity
    updatePeers()
  }
})

buttonCopy.addEventListener('click', () => {
  navigator.clipboard.writeText(inputPrivateKey.value).then(() => {
    customElements.get('pop-notify').notifyHtml('Private key copied!')
  })
})

buttonSendMessage.addEventListener('click', async () => {
  const dest_hex = inputSendAddress.value
  const theirAnnounce = peers[dest_hex]

  if (!theirAnnounce) {
    console.error(`Could not find announce for ${dest_hex}`)
    customElements.get('pop-notify').notifyHtml('Error: Unknown peer')
    return
  }

  if (!theirAnnounce.ratchet || theirAnnounce.ratchet.length === 0) {
    console.error(`Peer ${dest_hex} has no ratchet`)
    customElements.get('pop-notify').notifyHtml('Error: Peer has no ratchet')
    return
  }

  try {
    // Convert public_key and ratchet from localStorage objects to Uint8Array
    const public_key = theirAnnounce.public_key instanceof Uint8Array ? theirAnnounce.public_key : new Uint8Array(Object.values(theirAnnounce.public_key))
    const ratchet = theirAnnounce.ratchet instanceof Uint8Array ? theirAnnounce.ratchet : new Uint8Array(Object.values(theirAnnounce.ratchet))

    const destination_hash = get_identity_destination_hash(public_key)

    // Build LXMF message - content and title should be strings
    const title = inputSendTitle.value || ''
    const lxmf_message = lxmf_build(inputSendBody.value, identity.private, destination_hash, identity.destination_hash, null, title)

    // Build DATA packet
    const data_packet = await build_data(lxmf_message, public_key, ratchet)

    // Store sent message for PROOF validation
    const response_packet = packet_unpack(data_packet)
    sent_messages.set(toHex(response_packet.packet_hash), {
      packet_bytes: data_packet,
      sender_pub: public_key
    })

    ws.send(data_packet)

    console.log(`Sent message to ${dest_hex.slice(0, 16)}...`)
    dialogPopupMessage.close()
    customElements.get('pop-notify').notifyHtml('Message sent.')
  } catch (e) {
    console.error('Send failed:', e)
    customElements.get('pop-notify').notifyHtml(`Error: ${e.message}`)
  }
})

for (const b of document.querySelectorAll('.closeDialogPopupMessage')) {
  b.addEventListener('click', () => {
    dialogPopupMessage.close()
  })
}

// WebSocket connection
function connect() {
  ws = new WebSocket(WS_URL)
  ws.binaryType = 'arraybuffer'

  ws.addEventListener('open', () => {
    console.log(`Connected to ${WS_URL}`)
    if (identity) {
      announce()
    }
  })

  ws.addEventListener('message', (e) => handlePacket(e.data))

  ws.addEventListener('error', (e) => console.error('WebSocket error:', e))

  ws.addEventListener('close', () => {
    console.log('Disconnected. Reconnecting in 5 seconds...')
    setTimeout(connect, 5000)
  })
}

// Initialize
updatePeers()
connect()
