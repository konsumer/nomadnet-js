import WebSocket from 'ws'

// prettier-ignore
import {
  private_identity,
  public_identity,
  private_ratchet,
  public_ratchet,
  packet_unpack,
  build_announce,
  build_data,
  build_proof,
  validate_announce,
  validate_proof,
  message_decrypt,
  lxmf_parse,
  lxmf_build,
  get_identity_destination_hash,
  PACKET_DATA,
  PACKET_ANNOUNCE,
  PACKET_PROOF
} from '../src/index.js'

const WS_URL = 'wss://signal.konsumer.workers.dev/ws/reticulum'

const packet_names = {
  [PACKET_DATA]: 'DATA',
  [PACKET_ANNOUNCE]: 'ANNOUNCE',
  [PACKET_PROOF]: 'PROOF'
}

// Convert Uint8Array to hex string
function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// Periodically ANNOUNCE
async function announceHandler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub, interval = 30000) {
  while (ws.readyState === WebSocket.OPEN) {
    console.log(`ANNOUNCE me ${toHex(me_dest)}`)
    const pkt = build_announce(me_priv, null, me_dest, ratchet_priv, ratchet_pub)
    ws.send(pkt)
    await new Promise((resolve) => setTimeout(resolve, interval))
  }
}

// Handle incoming packets
async function packetHandler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub) {
  // This will store ANNOUNCE packets, for decrypting DATAs
  const announces = new Map()

  // This will store sent-messages for verifying PROOFs
  const sent_messages = new Map()

  ws.on('message', async (packet_bytes) => {
    const packet = packet_unpack(new Uint8Array(packet_bytes))
    console.log(`${packet_names[packet.packet_type]} (${toHex(packet.destination_hash)})`)

    try {
      if (packet.packet_type === PACKET_ANNOUNCE) {
        const announce = validate_announce(packet)
        if (!announce) {
          throw new Error('Invalid ANNOUNCE')
        }
        console.log('  Valid: True')
        announces.set(toHex(packet.destination_hash), announce)
      }

      if (packet.packet_type === PACKET_DATA) {
        const me_dest_hex = toHex(me_dest)
        const dest_hex = toHex(packet.destination_hash)

        if (dest_hex === me_dest_hex) {
          const data = await message_decrypt(packet, me_pub, [ratchet_priv])
          if (!data) {
            throw new Error('Invalid DATA - cannot decrypt')
          }
          console.log('  For me: True')

          // Parse LXMF message - need sender's announce for public key
          const source_hash = data.slice(0, 16)
          const source_hash_hex = toHex(source_hash)
          const sender_announce = announces.get(source_hash_hex)

          if (!sender_announce) {
            console.log(`  Sender ${source_hash_hex.slice(0, 16)}... not in announces`)
            return
          }

          const lxmf = lxmf_parse(data, me_dest, sender_announce.public_key)
          if (!lxmf) {
            console.log('  Invalid LXMF message')
            return
          }

          console.log(`  From: ${toHex(lxmf.source_hash)}`)
          console.log(`  Content: ${lxmf.content || '(no content)'}`)

          // Send PROOF back
          const proof_bytes = build_proof(packet.raw, me_priv)
          ws.send(proof_bytes)
          console.log('  Sent PROOF')

          // Send echo response DATA back to sender
          if (sender_announce.ratchet && sender_announce.ratchet.length > 0) {
            try {
              // Build LXMF response message
              // IMPORTANT: Preserve content type (string vs binary) to maintain msgpack encoding
              // If content is a string, keep it as string. If binary, ensure it's Uint8Array
              let response_content = lxmf.content || new Uint8Array(0)
              if (typeof response_content !== 'string' && !(response_content instanceof Uint8Array)) {
                // Convert Buffer to Uint8Array if needed
                response_content = new Uint8Array(response_content)
              }
              console.log('  Echo content type:', typeof response_content === 'string' ? 'string' : response_content.constructor.name, 'length:', response_content.length)
              console.log('  Fields type:', lxmf.fields.constructor.name)
              console.log('  Incoming source_hash (sender dest):', toHex(lxmf.source_hash))
              console.log('  Our dest:', toHex(me_dest))
              console.log('  Sender pub key:', toHex(sender_announce.public_key))

              // CRITICAL: The destination_hash we sign with MUST match what build_data will use
              // build_data computes: get_identity_destination_hash(receiver_pub)
              const response_destination = get_identity_destination_hash(sender_announce.public_key)
              console.log('  Computed sender dest from pub key:', toHex(response_destination))
              console.log('  Match with LXMF source_hash?', toHex(lxmf.source_hash) === toHex(response_destination))

              const lxmf_response = lxmf_build(
                response_content,
                me_priv,
                response_destination, // MUST use computed destination from pub key!
                me_dest, // Source = us
                null, // timestamp - will be auto-generated
                lxmf.fields // IMPORTANT: Pass through fields to preserve encoding
              )

              console.log('  LXMF response source hash (bytes 0-16):', toHex(lxmf_response.slice(0, 16)))
              console.log('  LXMF response signature (bytes 16-80):', toHex(lxmf_response.slice(16, 80)))
              console.log('  LXMF response msgpack first 50 bytes:', toHex(lxmf_response.slice(80, 130)))

              // Encrypt and send
              const response_data = await build_data(lxmf_response, sender_announce.public_key, sender_announce.ratchet)

              // Check the DATA packet destination
              const response_packet_check = packet_unpack(response_data)
              console.log('  DATA packet destination_hash:', toHex(response_packet_check.destination_hash))

              ws.send(response_data)

              // Store sent message for PROOF validation
              const response_packet = packet_unpack(response_data)
              sent_messages.set(toHex(response_packet.packet_hash), {
                packet_bytes: response_data,
                sender_pub: sender_announce.public_key
              })
              console.log(`  Sent DATA echo to ${source_hash_hex.slice(0, 16)}...`)
            } catch (e) {
              console.log(`  Failed to echo: ${e.message}`)
            }
          } else {
            console.log('  Cannot respond - sender has no ratchet')
          }
        } else {
          console.log('  For me: False')
        }
      }

      if (packet.packet_type === PACKET_PROOF) {
        // Validate PROOF against our sent messages
        const truncated_msg_id = toHex(packet.destination_hash)

        // Check if this PROOF is for one of our sent messages
        let found = false
        let msg_to_delete = null

        for (const [msg_hash, msg_info] of sent_messages.entries()) {
          if (msg_hash.startsWith(truncated_msg_id)) {
            // Validate the proof
            const full_hash = new Uint8Array(msg_hash.length / 2)
            for (let i = 0; i < full_hash.length; i++) {
              full_hash[i] = parseInt(msg_hash.substr(i * 2, 2), 16)
            }
            const is_valid = validate_proof(packet, msg_info.sender_pub, full_hash)
            console.log(`  Valid: ${is_valid}`)
            if (is_valid) {
              msg_to_delete = msg_hash
            }
            found = true
            break
          }
        }

        if (msg_to_delete) {
          sent_messages.delete(msg_to_delete)
        }

        if (!found) {
          console.log('  Not for any of our sent messages')
        }
      }
    } catch (e) {
      console.log(`  Failed: ${e.message}`)
    }
  })

  ws.on('error', (err) => {
    console.error('WebSocket error:', err)
  })

  ws.on('close', () => {
    console.log('WebSocket closed')
  })
}

async function main() {
  // Setup my identity
  const me_priv = private_identity()
  const me_pub = public_identity(me_priv)
  const me_dest = get_identity_destination_hash(me_pub)
  const ratchet_priv = private_ratchet()
  const ratchet_pub = public_ratchet(ratchet_priv)

  function connect() {
    const ws = new WebSocket(WS_URL)

    ws.on('open', () => {
      console.log(`Connected to ${WS_URL}`)

      // Start handlers
      announceHandler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub)
      packetHandler(ws, me_priv, me_pub, me_dest, ratchet_priv, ratchet_pub)
    })

    ws.on('close', () => {
      console.log('Disconnected. Reconnecting in 5 seconds...')
      setTimeout(connect, 5000)
    })

    ws.on('error', (err) => {
      console.error('Connection error:', err.message)
    })
  }

  connect()
}

main()
