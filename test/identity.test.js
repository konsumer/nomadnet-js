import { describe, test } from 'node:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import assert from 'node:assert'
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js'

import { unserializeIdentity, serializeIdentity, generateIdentity, pubFromPrivate, getLxmfIdentity } from '../src/index.js'

let key
let pub

const encoder = new TextEncoder()

describe('Identity', () => {
  test('unserializeIdentity', () => {
    // this was pulled from nomad identity file
    // rnid -x -i demo/a/nomad/storage/identity
    key = unserializeIdentity('308a69c6e147ea856912d2377e56e0c9560ea2f9da0e7743009499b6a262b846ea748b08ea8f473111ff2e63ed24603991da24a40745a9a93f53616a8d35d47c')
    assert.ok(key.encPriv)
    assert.ok(key.sigPriv)
  })

  test('serializeIdentity', () => {
    const p = serializeIdentity(key)
    assert.equal(p, '308a69c6e147ea856912d2377e56e0c9560ea2f9da0e7743009499b6a262b846ea748b08ea8f473111ff2e63ed24603991da24a40745a9a93f53616a8d35d47c')
  })

  test('generateIdentity', () => {
    const p = generateIdentity()
    assert.ok(p.encPriv)
    assert.ok(p.sigPriv)
  })

  test('pubFromPrivate', () => {
    pub = pubFromPrivate(key)
    assert.ok(pub.encPub)
    assert.ok(pub.sigPub)

    // use priv to sign, then verify with pub
    const msg = encoder.encode('cool test')
    const sig = ed25519.sign(msg, key.sigPriv)
    assert.ok(ed25519.verify(sig, msg, pub.sigPub))
  })

  test('getLxmfIdentity', () => {
    // LXMF address
    const lxmf = getLxmfIdentity(pub)
    assert.equal(bytesToHex(lxmf.destinationHash), '848ee1c5fa95580b9801e1932590e3cb')
  })
})
