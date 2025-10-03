// test creating a message, for use with python (for verification)

import { test, describe } from 'node:test'

import { unserializeIdentity, buildMessage, buildPacket, loadPacket, processMessage } from '../src/index.js'
import { keys, ratchets } from '../examples/demo_data.js'
import { bytesToHex } from '@noble/curves/utils.js'

const ALLOW_LOG = false
const testLog = ALLOW_LOG ? console.trace : () => {}

const clientA = unserializeIdentity(keys.clientA)
const clientB = unserializeIdentity(keys.clientB)
const identities = {
  [clientA.destinationHash]: clientA,
  [clientB.destinationHash]: clientB
}

let messageBytes

describe('Messages', () => {
  test('create message', () => {
    messageBytes = buildPacket(buildMessage({ content: 'Hello from Javascript!' }, clientA.destinationHash, ratchets[0], clientA.identityHash))
    // use this in python
    testLog('Paste this into python test', bytesToHex(messageBytes))
  })

  test('read message', () => {
    const packet = loadPacket(messageBytes)
    testLog(packet)
    const parsed = processMessage(packet, identities[packet.destinationHash], ratchets)
    testLog(parsed)
  })
})
