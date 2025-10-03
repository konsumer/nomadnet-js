import { test, describe } from 'node:test'

import * as nomad from '../src/index.js'
import * as demo from '../examples/demo_data.js'
import { bytesToHex } from '@noble/curves/utils.js'

let identity
let serialized

describe('Identity', () => {
	test('generateIdentity', ({ assert }) => {
		identity = nomad.generateIdentity()
		assert.deepEqual(Object.keys(identity), ['encPriv', 'sigPriv', 'encPub', 'sigPub', 'identityHash', 'destinationHash'])
	})

	test('serializeIdentity', ({ assert }) => {
		// test the identity made in generateIdentity
		serialized=nomad.serializeIdentity(identity)
		assert.equal(serialized.length, 128)
	})
	
	test('unserializeIdentity', ({ assert }) => {
		// test the identity made in generateIdentity, and serialized in serializeIdentity
		const deserial = nomad.unserializeIdentity(serialized)
		for (const k of Object.keys(identity)) {
			assert.deepEqual(deserial[k], identity[k])
		}

		// test some pre-made identites for known-values
		const deserialA = nomad.unserializeIdentity(demo.keys.clientA)
		assert.equal(bytesToHex(deserialA.destinationHash), '072ec44973a8dee8e28d230fb4af8fe4')
		assert.equal(bytesToHex(deserialA.encPriv), '205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b93167')
		assert.equal(bytesToHex(deserialA.encPub), 'a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738')
		assert.equal(bytesToHex(deserialA.sigPriv), '7763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313')
		assert.equal(bytesToHex(deserialA.sigPub), 'da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece')

		const deserialB = nomad.unserializeIdentity(demo.keys.clientB)
		assert.equal(bytesToHex(deserialB.destinationHash), '76a93cda889a8c0a88451e02d53fd8b9')
		assert.equal(bytesToHex(deserialB.encPriv), 'e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759')
		assert.equal(bytesToHex(deserialB.encPub), '71f199f04d3589ca083c66ff91baed628ee19517ef68eb209827df3a6785cf5b')
		assert.equal(bytesToHex(deserialB.sigPriv), '142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
		assert.equal(bytesToHex(deserialB.sigPub), '0af43fb0e168176370828fcdc199e5ae2b208b57cf65179ffa8f25733d9d40bc')
	})
})

    
