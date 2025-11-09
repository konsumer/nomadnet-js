import { describe, test } from 'node:test'

// prettier-ignore
import {
    build_announce,
    build_data,
    build_proof,
    CONTEXT_NONE,
    CONTEXT_RESOURCE,
    DEST_GROUP,
    DEST_SINGLE,
    get_identity_destination_hash,
    lxmf_build,
    lxmf_parse,
    message_decrypt,
    PACKET_ANNOUNCE,
    PACKET_DATA,
    packet_pack,
    PACKET_PROOF,
    packet_unpack,
    private_identity,
    private_ratchet,
    public_identity,
    public_ratchet,
    validate_announce,
    validate_proof
} from '../src/index.js'

describe('Packet Pack/Unpack', () => {
  test('packet_pack and packet_unpack roundtrip', ({ assert }) => {
    // Create a simple packet dict
    const packet = {
      header_type: 0,
      context_flag: 0,
      transport_type: 0,
      destination_type: DEST_SINGLE,
      packet_type: PACKET_DATA,
      hops: 0,
      destination_hash: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
      context: CONTEXT_NONE,
      data: new TextEncoder().encode('hello world')
    }

    // Pack it
    const packed = packet_pack(packet)

    // Unpack it
    const unpacked = packet_unpack(packed)

    // Verify key fields match
    assert.equal(unpacked.header_type, packet.header_type)
    assert.equal(unpacked.context_flag, packet.context_flag)
    assert.equal(unpacked.transport_type, packet.transport_type)
    assert.equal(unpacked.destination_type, packet.destination_type)
    assert.equal(unpacked.packet_type, packet.packet_type)
    assert.equal(unpacked.hops, packet.hops)
    assert.deepEqual(unpacked.destination_hash, packet.destination_hash)
    assert.equal(unpacked.context, packet.context)
    assert.deepEqual(unpacked.data, packet.data)
  })

  test('packet_pack with transport_id (header_type=1)', ({ assert }) => {
    const packet = {
      header_type: 1,
      context_flag: 1,
      transport_type: 1,
      destination_type: DEST_GROUP,
      packet_type: PACKET_ANNOUNCE,
      hops: 5,
      transport_id: new Uint8Array([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]),
      destination_hash: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
      context: CONTEXT_RESOURCE,
      data: new TextEncoder().encode('test data')
    }

    const packed = packet_pack(packet)
    const unpacked = packet_unpack(packed)

    assert.equal(unpacked.header_type, 1)
    assert.deepEqual(unpacked.transport_id, packet.transport_id)
    assert.deepEqual(unpacked.destination_hash, packet.destination_hash)
    assert.deepEqual(unpacked.data, packet.data)
  })
})

describe('Build ANNOUNCE', () => {
  test('build_announce basic without ratchet', ({ assert }) => {
    const identity_priv = private_identity()
    const identity_pub = public_identity(identity_priv)

    // Build announce
    const announce_bytes = build_announce(identity_priv)

    // Unpack and validate
    const packet = packet_unpack(announce_bytes)
    assert.equal(packet.packet_type, PACKET_ANNOUNCE)
    assert.equal(packet.destination_type, DEST_SINGLE)
    assert.equal(packet.context_flag, 0)

    // Validate the announce
    const result = validate_announce(packet)
    assert.notEqual(result, false)
    assert.deepEqual(result.public_key, identity_pub)
  })

  test('build_announce with ratchet', ({ assert }) => {
    const identity_priv = private_identity()
    const identity_pub = public_identity(identity_priv)
    const ratchet_priv = private_ratchet()
    const ratchet_pub = public_ratchet(ratchet_priv)

    // Build announce with ratchet
    const announce_bytes = build_announce(identity_priv, null, null, ratchet_priv)

    // Unpack and validate
    const packet = packet_unpack(announce_bytes)
    assert.equal(packet.packet_type, PACKET_ANNOUNCE)
    assert.equal(packet.context_flag, 1) // Should have ratchet

    // Validate the announce
    const result = validate_announce(packet)
    assert.notEqual(result, false)
    assert.deepEqual(result.public_key, identity_pub)
    assert.deepEqual(result.ratchet, ratchet_pub)
  })

  test('build_announce with app_data', ({ assert }) => {
    const identity_priv = private_identity()
    const app_data = new TextEncoder().encode('test app data')

    // Build announce with app data
    const announce_bytes = build_announce(identity_priv, null, null, null, null, 'lxmf.delivery', app_data)

    // Unpack and validate
    const packet = packet_unpack(announce_bytes)
    const result = validate_announce(packet)
    assert.notEqual(result, false)
    assert.deepEqual(result.app_data, app_data)
  })
})

describe('Build DATA', () => {
  test('build_data basic encryption and decryption', ({ assert }) => {
    // Create sender and receiver identities
    const receiver_priv = private_identity()
    const receiver_pub = public_identity(receiver_priv)

    // Create receiver's ratchet
    const receiver_ratchet_priv = private_ratchet()
    const receiver_ratchet_pub = public_ratchet(receiver_ratchet_priv)

    // Build data packet
    const plaintext = new TextEncoder().encode('Hello, World!')
    const data_bytes = build_data(plaintext, receiver_pub, receiver_ratchet_pub)

    // Unpack
    const packet = packet_unpack(data_bytes)
    assert.equal(packet.packet_type, PACKET_DATA)
    assert.equal(packet.destination_type, DEST_SINGLE)

    // Decrypt
    const decrypted = message_decrypt(packet, receiver_pub, [receiver_ratchet_priv])
    assert.notEqual(decrypted, null)
    assert.deepEqual(decrypted, plaintext)
  })

  test('build_data cannot be decrypted with wrong ratchet', ({ assert }) => {
    const receiver_priv = private_identity()
    const receiver_pub = public_identity(receiver_priv)

    // Create receiver's ratchet
    const receiver_ratchet_pub = public_ratchet(private_ratchet())

    // Create a different ratchet for decryption (wrong one)
    const wrong_ratchet_priv = private_ratchet()

    // Build data packet
    const plaintext = new TextEncoder().encode('Secret message')
    const data_bytes = build_data(plaintext, receiver_pub, receiver_ratchet_pub)

    // Try to decrypt with wrong ratchet
    const packet = packet_unpack(data_bytes)
    const decrypted = message_decrypt(packet, receiver_pub, [wrong_ratchet_priv])
    assert.equal(decrypted, null)
  })
})

describe('Build PROOF', () => {
  test('build_proof basic validation', ({ assert }) => {
    // Create sender identity
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)

    // Create a dummy data packet
    const receiver_priv = private_identity()
    const receiver_pub = public_identity(receiver_priv)
    const receiver_ratchet_pub = public_ratchet(private_ratchet())

    // Build data and get message ID
    const data_bytes = build_data(new TextEncoder().encode('test'), receiver_pub, receiver_ratchet_pub)
    const data_packet = packet_unpack(data_bytes)
    const full_message_id = data_packet.packet_hash

    // Build proof
    const proof_bytes = build_proof(data_bytes, sender_priv)

    // Unpack
    const proof_packet = packet_unpack(proof_bytes)
    assert.equal(proof_packet.packet_type, PACKET_PROOF)

    // The proof destination should be the truncated message ID (first 16 bytes)
    assert.deepEqual(proof_packet.destination_hash, full_message_id.slice(0, 16))

    // Validate proof
    const valid = validate_proof(proof_packet, sender_pub, full_message_id)
    assert.ok(valid)
  })

  test('build_proof fails with wrong sender', ({ assert }) => {
    // Create sender and wrong identity
    const sender_priv = private_identity()
    const wrong_pub = public_identity(private_identity())

    // Create a dummy data packet
    const receiver_priv = private_identity()
    const receiver_pub = public_identity(receiver_priv)
    const receiver_ratchet_pub = public_ratchet(private_ratchet())

    const data_bytes = build_data(new TextEncoder().encode('test'), receiver_pub, receiver_ratchet_pub)
    const data_packet = packet_unpack(data_bytes)
    const full_message_id = data_packet.packet_hash

    // Build proof
    const proof_bytes = build_proof(data_bytes, sender_priv)
    const proof_packet = packet_unpack(proof_bytes)

    // Try to validate with wrong sender
    const is_valid = validate_proof(proof_packet, wrong_pub, full_message_id)
    assert.equal(is_valid, false)
  })
})

describe('End-to-End Flow', () => {
  test('full message exchange: ANNOUNCE -> DATA -> PROOF', ({ assert }) => {
    // Alice creates identity and announces
    const alice_priv = private_identity()
    const alice_pub = public_identity(alice_priv)
    const alice_ratchet_priv = private_ratchet()

    const alice_announce = build_announce(alice_priv, null, null, alice_ratchet_priv)
    const alice_announce_packet = packet_unpack(alice_announce)
    const alice_announce_info = validate_announce(alice_announce_packet)
    assert.notEqual(alice_announce_info, false)

    // Bob creates identity
    const bob_priv = private_identity()

    // Bob sends data to Alice using her announced ratchet
    const message = new TextEncoder().encode('Hello Alice!')
    const data_bytes = build_data(message, alice_pub, alice_announce_info.ratchet)
    const data_packet = packet_unpack(data_bytes)

    // Alice decrypts the message
    const decrypted = message_decrypt(data_packet, alice_pub, [alice_ratchet_priv])
    assert.deepEqual(decrypted, message)

    // Alice sends a proof back to Bob
    const proof_bytes = build_proof(data_bytes, alice_priv)
    const proof_packet = packet_unpack(proof_bytes)

    // Bob validates the proof
    const is_valid = validate_proof(proof_packet, alice_pub, data_packet.packet_hash)
    assert.equal(is_valid, true)
  })
})

describe('LXMF', () => {
  test('lxmf_build basic', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_dest = get_identity_destination_hash(public_identity(sender_priv))
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const content = new TextEncoder().encode('Hello')
    const lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)

    // Verify structure
    assert.ok(lxmf_msg.length >= 80)
    assert.deepEqual(lxmf_msg.slice(0, 16), sender_dest) // source hash
  })

  test('lxmf_build with custom fields', ({ assert }) => {
    const sender_priv = private_identity()
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const content = new TextEncoder().encode('Test')
    const timestamp = 1234567890.0
    const fields = { custom: 'data' }

    const lxmf_msg = lxmf_build(content, sender_priv, receiver_dest, null, timestamp, null, fields)
    assert.ok(lxmf_msg.length >= 80)
  })

  test('lxmf_build auto source_hash', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_dest = get_identity_destination_hash(public_identity(sender_priv))
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const lxmf_msg = lxmf_build(new TextEncoder().encode('test'), sender_priv, receiver_dest)
    assert.deepEqual(lxmf_msg.slice(0, 16), sender_dest)
  })

  test('lxmf_parse basic', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)
    const sender_dest = get_identity_destination_hash(sender_pub)
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const content = new TextEncoder().encode('Hello World!')
    const lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)

    const parsed = lxmf_parse(lxmf_msg, receiver_dest, sender_pub)
    assert.notEqual(parsed, false)
    assert.deepEqual(parsed.source_hash, sender_dest)
    assert.deepEqual(parsed.content, content)
    assert.ok('timestamp' in parsed)
    assert.ok('fields' in parsed)
    assert.ok('message_id' in parsed)
  })

  test('lxmf_parse invalid signature', ({ assert }) => {
    const sender_priv = private_identity()
    const wrong_pub = public_identity(private_identity())
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const lxmf_msg = lxmf_build(new TextEncoder().encode('test'), sender_priv, receiver_dest)

    // Try parsing with wrong public key
    const parsed = lxmf_parse(lxmf_msg, receiver_dest, wrong_pub)
    assert.notEqual(parsed, false)
    assert.equal(parsed.valid, false)
  })

  test('lxmf_parse too short', ({ assert }) => {
    const sender_pub = public_identity(private_identity())
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const parsed = lxmf_parse(new TextEncoder().encode('short'), receiver_dest, sender_pub)
    assert.equal(parsed, false)
  })

  test('lxmf_parse corrupted msgpack', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)
    const sender_dest = get_identity_destination_hash(sender_pub)
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    // Create valid structure but corrupt msgpack
    const corrupted = new Uint8Array(80 + 25)
    corrupted.set(sender_dest, 0)
    corrupted.set(new TextEncoder().encode('invalid msgpack data here'), 80)

    const parsed = lxmf_parse(corrupted, receiver_dest, sender_pub)
    assert.equal(parsed, false)
  })

  test('lxmf roundtrip', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)
    const sender_dest = get_identity_destination_hash(sender_pub)
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    const content = new TextEncoder().encode('Roundtrip test message')
    const lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)
    const parsed = lxmf_parse(lxmf_msg, receiver_dest, sender_pub)

    assert.notEqual(parsed, false)
    assert.deepEqual(parsed.source_hash, sender_dest)
    assert.deepEqual(parsed.content, content)
  })

  test('lxmf with string content (text message)', ({ assert }) => {
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)
    const sender_dest = get_identity_destination_hash(sender_pub)
    const receiver_dest = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    // Use string content (as Nomadnet would send)
    const content = 'Hello from Nomadnet'
    const lxmf_msg = lxmf_build(content, sender_priv, receiver_dest)
    const parsed = lxmf_parse(lxmf_msg, receiver_dest, sender_pub)

    assert.notEqual(parsed, false)
    assert.deepEqual(parsed.source_hash, sender_dest)
    // Content is now Uint8Array bytes, decode to compare
    const decoder = new TextDecoder()
    assert.equal(decoder.decode(parsed.content), content)
  })
})

describe('LXMF Integration', () => {
  test('lxmf_message_build_and_parse', ({ assert }) => {
    // Create sender and receiver identities
    const sender_priv = private_identity()
    const sender_pub = public_identity(sender_priv)
    const sender_dest = get_identity_destination_hash(sender_pub)

    const receiver_priv = private_identity()
    const receiver_pub = public_identity(receiver_priv)
    const receiver_dest = get_identity_destination_hash(receiver_pub)

    // Build LXMF message
    const content = new TextEncoder().encode('Hello World!')
    const lxmf_message = lxmf_build(content, sender_priv, receiver_dest)

    // Parse it back (receiver_dest is the packet destination in this case)
    const parsed = lxmf_parse(lxmf_message, receiver_dest, sender_pub)

    assert.notEqual(parsed, false)
    assert.deepEqual(parsed.source_hash, sender_dest)
    assert.deepEqual(parsed.content, content)
  })

  test('lxmf_full_encrypted_flow', ({ assert }) => {
    // Create sender (Bob) and receiver (Alice) identities
    const alice_priv = private_identity()
    const alice_pub = public_identity(alice_priv)
    const alice_dest = get_identity_destination_hash(alice_pub)
    const alice_ratchet_priv = private_ratchet()
    const alice_ratchet_pub = public_ratchet(alice_ratchet_priv)

    const bob_priv = private_identity()
    const bob_pub = public_identity(bob_priv)
    const bob_dest = get_identity_destination_hash(bob_pub)
    const bob_ratchet_priv = private_ratchet()

    // Bob announces with ratchet
    const bob_announce = build_announce(bob_priv, null, null, bob_ratchet_priv)
    const bob_announce_packet = packet_unpack(bob_announce)
    const bob_announce_info = validate_announce(bob_announce_packet)

    // Alice announces with ratchet
    const alice_announce = build_announce(alice_priv, null, null, alice_ratchet_priv)
    const alice_announce_packet = packet_unpack(alice_announce)

    // Bob builds LXMF message to Alice
    const content = new TextEncoder().encode('Hello Alice from Bob!')
    const lxmf_message = lxmf_build(content, bob_priv, alice_dest)

    // Bob encrypts it in a DATA packet
    const data_bytes = build_data(lxmf_message, alice_pub, alice_ratchet_pub)
    const data_packet = packet_unpack(data_bytes)

    // Alice decrypts the DATA packet
    const decrypted = message_decrypt(data_packet, alice_pub, [alice_ratchet_priv])
    assert.notEqual(decrypted, null)

    // Alice parses the LXMF message (alice_dest is the packet destination)
    const parsed = lxmf_parse(decrypted, alice_dest, bob_pub)
    assert.notEqual(parsed, false)
    assert.deepEqual(parsed.source_hash, bob_dest)
    assert.deepEqual(parsed.content, content)

    // Alice responds with echo
    const response_lxmf = lxmf_build(content, alice_priv, bob_dest)
    const response_data = build_data(response_lxmf, bob_pub, bob_announce_info.ratchet)
    const response_packet = packet_unpack(response_data)

    // Bob decrypts the response
    const response_decrypted = message_decrypt(response_packet, bob_pub, [bob_ratchet_priv])
    assert.notEqual(response_decrypted, null)

    // Bob parses the LXMF response (bob_dest is the packet destination)
    const response_parsed = lxmf_parse(response_decrypted, bob_dest, alice_pub)
    assert.notEqual(response_parsed, false)
    assert.deepEqual(response_parsed.source_hash, alice_dest)
    assert.deepEqual(response_parsed.content, content)
  })

  test('lxmf_echo_with_string_content', ({ assert }) => {
    // Simulate Nomadnet sending text to echobot and getting echo back
    const alice_priv = private_identity()
    const alice_pub = public_identity(alice_priv)
    const alice_dest = get_identity_destination_hash(alice_pub)
    const alice_ratchet_priv = private_ratchet()
    const alice_ratchet_pub = public_ratchet(alice_ratchet_priv)

    const bob_priv = private_identity()
    const bob_pub = public_identity(bob_priv)
    const bob_dest = get_identity_destination_hash(bob_pub)
    const bob_ratchet_priv = private_ratchet()
    const bob_ratchet_pub = public_ratchet(bob_ratchet_priv)

    // Alice sends TEXT message to Bob (as Nomadnet would)
    const text_content = 'Hello Bob!' // String, not bytes
    const lxmf_message = lxmf_build(text_content, alice_priv, bob_dest)
    const data_bytes = build_data(lxmf_message, bob_pub, bob_ratchet_pub)
    const data_packet = packet_unpack(data_bytes)

    // Bob decrypts and parses
    const decrypted = message_decrypt(data_packet, bob_pub, [bob_ratchet_priv])
    assert.notEqual(decrypted, null)
    const parsed = lxmf_parse(decrypted, bob_dest, alice_pub)
    assert.notEqual(parsed, false)
    // Content is now Uint8Array bytes, decode to compare
    const decoder = new TextDecoder()
    assert.equal(decoder.decode(parsed.content), text_content)

    // Bob echoes back - parsed.content is Uint8Array, can pass directly or as string
    const echo_content = parsed.content // Keep as bytes
    const echo_lxmf = lxmf_build(echo_content, bob_priv, alice_dest)
    const echo_data = build_data(echo_lxmf, alice_pub, alice_ratchet_pub)
    const echo_packet = packet_unpack(echo_data)

    // Alice receives echo
    const echo_decrypted = message_decrypt(echo_packet, alice_pub, [alice_ratchet_priv])
    assert.notEqual(echo_decrypted, null)
    const echo_parsed = lxmf_parse(echo_decrypted, alice_dest, bob_pub)
    assert.notEqual(echo_parsed, false)
    // Content is now Uint8Array bytes, decode to compare
    assert.equal(decoder.decode(echo_parsed.content), text_content)
    assert.ok(echo_parsed.content instanceof Uint8Array)
  })
})
