// Cross-validation tests between JavaScript and Python RNS implementations
// This simulates real message flows between two clients

import { describe, test } from 'node:test'
import assert from 'node:assert'
import { exec } from 'node:child_process'
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js'
import { getIdentityFromBytes, getDestinationHash, buildAnnounce, announceParse, decodePacket, buildProof, proofValidate, PACKET_ANNOUNCE, PACKET_DATA, PACKET_PROOF } from '../src/index.js'

// Helper to call Python RNS functions
const pyRNS = (op, args = {}) =>
  new Promise((resolve, reject) => {
    const argsJson = JSON.stringify(args).replace(/'/g, "\\\\'")
    exec(`python test/packet_checker.py ${op} '${argsJson}'`, (error, stdout, stderr) => {
      if (stderr) {
        console.log('Python stderr:', stderr)
      }
      if (error) {
        return reject(error)
      }
      try {
        const result = JSON.parse(stdout)
        if (result.error) {
          console.error('Python error:', result.error)
          if (result.traceback) {
            console.error(result.traceback)
          }
          return reject(new Error(result.error))
        }
        return resolve(result)
      } catch (e) {
        console.error('Failed to parse Python output:', stdout)
        reject(e)
      }
    })
  })

// me: 072ec44973a8dee8e28d230fb4af8fe4
const identityBytes = hexToBytes('205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313')
const identity = getIdentityFromBytes(identityBytes)
const identityDest = getDestinationHash(identity, 'lxmf.delivery')

// them: 76a93cda889a8c0a88451e02d53fd8b9
const otherBytes = hexToBytes('e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
const other = getIdentityFromBytes(otherBytes)
const otherDest = getDestinationHash(other, 'lxmf.delivery')

describe('Bidirectional Python-JS Message Flows', () => {
  // I have lots of other tests for getIdentityFromBytes/getDestinationHash, so this is just to make sure IDs are valid
  test('ID check', () => {
    assert.equal(bytesToHex(identityDest), '072ec44973a8dee8e28d230fb4af8fe4')
    assert.equal(bytesToHex(otherDest), '76a93cda889a8c0a88451e02d53fd8b9')
  })

  // this just checks connectivity, and verifies that python got the right IDs
  test('Python ID check', async () => {
    const t = await pyRNS('idcheck')
    assert.equal(t.me, '76a93cda889a8c0a88451e02d53fd8b9')
    assert.equal(t.other, '072ec44973a8dee8e28d230fb4af8fe4')
  })

  test('ANNOUNCE: JS creates, Python verifies', async () => {
    // JS creates announce
    const announcePacket = buildAnnounce(identity, identityDest, 'lxmf.delivery')

    // Python verifies it
    const result = await pyRNS('verifyAnnounce', bytesToHex(announcePacket))

    assert.ok(result.valid, 'Python should validate JS announce')
    assert.equal(result.hash, bytesToHex(identityDest))
  })

  test('ANNOUNCE: Python creates, JS verifies', async () => {
    // Python creates announce
    const result = await pyRNS('announce', {
      appData: 'Python Client'
    })

    const announcePacket = hexToBytes(result.packet)
    console.log('Python announce packet:', result.packet)

    // JS parses and verifies it
    const decoded = decodePacket(announcePacket)
    assert.equal(decoded.packetType, PACKET_ANNOUNCE)

    const parsed = announceParse(decoded)
    console.log('JS parsed announce:', {
      valid: parsed.valid,
      hash: bytesToHex(parsed.destinationHash)
    })

    assert.ok(parsed.valid, 'JS should validate Python announce')
    assert.equal(bytesToHex(parsed.destinationHash), bytesToHex(otherDest))
  })

  test.skip('DATA + PROOF: JS sends DATA, Python sends PROOF, JS verifies', async () => {
    // JS creates DATA packet to Python
    const dataPacket = buildData(identity, otherDest, new TextEncoder().encode('Hello from JS'))

    console.log('JS DATA packet:', bytesToHex(dataPacket))

    // Python verifies DATA
    const dataVerify = await pyRNS('verifyData', {
      packet: bytesToHex(dataPacket)
    })

    console.log('Python DATA verification:', dataVerify)
    assert.ok(dataVerify.valid, 'Python should receive DATA correctly')

    // Python creates PROOF
    const proofResult = await pyRNS('createProof', {
      packet: bytesToHex(dataPacket)
    })

    console.log('Python PROOF packet:', proofResult.proof)

    const proofPacket = hexToBytes(proofResult.proof)
    const proofDecoded = decodePacket(proofPacket)
    assert.equal(proofDecoded.packetType, PACKET_PROOF)

    // JS verifies PROOF
    const messageId = hexToBytes(proofResult.packetHash)
    const isValid = proofValidate(proofDecoded, other, messageId)

    console.log('JS PROOF verification:', isValid)
    assert.ok(isValid, 'JS should validate Python PROOF')
  })

  test.skip('DATA + PROOF: Python sends DATA, JS sends PROOF, Python verifies', async () => {
    // Python creates DATA packet to JS
    const dataResult = await pyRNS('createData', {
      data: 'Hello from Python'
    })

    const dataPacket = hexToBytes(dataResult.packet)
    console.log('Python DATA packet:', dataResult.packet)

    // JS receives and verifies DATA
    const dataDecoded = decodePacket(dataPacket)
    assert.equal(dataDecoded.packetType, PACKET_DATA)
    assert.equal(bytesToHex(dataDecoded.destinationHash), bytesToHex(identityDest))

    console.log('JS received DATA for:', bytesToHex(dataDecoded.destinationHash))

    // JS creates PROOF
    const proofPacket = buildProof(identity, dataDecoded)
    console.log('JS PROOF packet:', bytesToHex(proofPacket))

    // Python verifies PROOF
    const proofVerify = await pyRNS('verifyProof', {
      proof: bytesToHex(proofPacket),
      originalPacket: dataResult.packet
    })

    console.log('Python PROOF verification:', proofVerify)
    assert.ok(proofVerify.valid, 'Python should validate JS PROOF')
  })
})
