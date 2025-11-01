// this tests real packets/identity from official clients and real traffic

import { describe, test } from 'node:test'
import assert from 'node:assert'
import { hexToBytes, bytesToHex, msgunpack } from '../src/utils.js'

// prettier-ignore
import {
  getDestinationHash,
  publicIdentity,
  publicRatchet,
  parsePacket,
  parseLxmf,
  parseAnnounce,
  parseProof,
  messageDecrypt,
  getMessageId,
  PACKET_DATA,
  PACKET_ANNOUNCE,
  PACKET_PROOF
} from '../src/index.js'

const keys = {
  '072ec44973a8dee8e28d230fb4af8fe4': hexToBytes('205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b931677763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313'),
  '76a93cda889a8c0a88451e02d53fd8b9': hexToBytes('e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
}

const ratchets = [hexToBytes('205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066'), hexToBytes('28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45')]

const packets = `
ANNOUNCE (072ec44973a8dee8e28d230fb4af8fe4):  2100072ec44973a8dee8e28d230fb4af8fe400a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece6ec60bc318e2c0f0d90873408275530068de1039e2bb21108b2cbc900b476290ab7867441446db366a70fb8ed1448ca0e889bd65bad6d8654e72661ddc089b06495ab91a57afc5700e095f021aa8cec04f22ba55438efc3ab1e2a91b8d17bd259313f175dff040827fdf1111c88bef501676380b92c40e416e6f6e796d6f75732050656572c0
ANNOUNCE (76a93cda889a8c0a88451e02d53fd8b9):  210076a93cda889a8c0a88451e02d53fd8b90071f199f04d3589ca083c66ff91baed628ee19517ef68eb209827df3a6785cf5b0af43fb0e168176370828fcdc199e5ae2b208b57cf65179ffa8f25733d9d40bc6ec60bc318e2c0f0d908149ad525040068de103b0df6d220011ce9da7559fbd620380501d9e19afce87a6d0c661412f3831cc915dbecabe89ef5a11a359d3757a85280c3ae68a8b6366ed4110be24a408dbe946b2815e0e89f8e49848978122b30e442af83b36cef11d3df69c34189156858560292c40e416e6f6e796d6f75732050656572c0
DATA (76a93cda889a8c0a88451e02d53fd8b9):  000076a93cda889a8c0a88451e02d53fd8b900f549cccf8d574cb520c8f12ea6ea67c4f4ce34f301de611cd942acbfb6933f3f7a025d5b6d6184d04dd0279b8037f1c9c1c1c25defbdd5e62aa8fb04502101014a501b9235e62f823bbdfd4d85e7656d765802f115a01b57b823ae02cc94899ae3a0f94bf7c32f1a73c027e5c95e0dd94c72c833ea75951af517da665eff26bca45e90e2eaa18775e65799ea0b3a977645107850dbfe62bb1f3228b50ac6e775006c4f18d6f3a1474233dc9b13cd95f6a6f581ad0b85de7196ea606d393d35f1
PROOF (2831d76f1a8035638505c132fe5818c1):  03002831d76f1a8035638505c132fe5818c100b90b83a04be319463f930b123b667eaaf64a85e827c34831a032cf72834a1dc58836e1fe4c49e30decab52747da2811db83a4b0b8464aa31e02f2eebbf1dae03
DATA (072ec44973a8dee8e28d230fb4af8fe4):  0000072ec44973a8dee8e28d230fb4af8fe400b2191b23b7506a3325fe288d75a7ab06700f92c710c16a7f55769afb014d753b8cf3187730116905843fb0de9dcec976b121a6425b995f80442819ebe883dab5aa72fb8a9d96849969b073b8e76e4463dc8c0eceba936665c4b62af1c31de32ba3433b6d5bf9ceaf4e08355126af0ef6dd111bdeeefa49434c69aba42160ec3e3698c2a88d96ef940b636dff89f2dbde337ae0fc7cd802de72793458dc3a1966fb0ed28e513dfc77138d53f87875a97a22e11e58191d5ae863de24ff68a3e961
PROOF (d7c0e833f0cbde9f9133cd9e7d508b1a):  0300d7c0e833f0cbde9f9133cd9e7d508b1a00cd00ce237471609d6ef64e427151fed46d9eb71fe6337f6fc530a9f3a55c730f1fd09f82f7d12d1caadbc185b7703f0d9f5db6c792c2dfcdf1eed3111088860c
`
  .split('\n')
  .filter((l) => l.trim())
  .map((l) => hexToBytes(l.split(':  ').pop()))

// problematic ANNOUNCE packets from other networks
packets.push(hexToBytes('01007d62e355cc90ec4e79569d33a8ad6c6b00b05e9bd83282a538be44ec872286cec32de7a8335e29c72fe8e8463ca135565b3a5580d45637aeaf037fe5f608b702a3ca85efcf231c68fbfd852706ac320695e03a09b77ac21b22258e299132c47b0068f2b1de03faecd1a563d18584e2f2b4a4434bd3e9a3fb943fa035cc2205b6f779de118908b7cad82cd4830d3a70ba7c8749af77dafbb6feb4023f988cae05b7ae83210894c2ce68f2b1decb4070000000000000c0'))
packets.push(hexToBytes('71014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308'))

// Track DATA packets for lookup in PROOF
// Normally this would happen when you send a message, but I do it in my DATA tests
const sentPackets = {}

// Build recipients & lookup table
// Put the addresses in easier-to-use shape
const recipients = {}

const decoder = new TextDecoder()

describe('Identity', () => {
  for (const hash of Object.keys(keys)) {
    test(`Client Identity ${hash}`, () => {
      const clientPrivate = keys[hash]
      const clientPublic = publicIdentity(keys[hash])
      const clientHash = getDestinationHash(clientPublic, 'lxmf.delivery')
      assert.equal(bytesToHex(clientHash), hash, 'address matches expected')
      recipients[clientHash] = [clientPrivate, clientPublic]
    })
  }
})

describe('ANNOUNCE', () => {
  test('072ec44973a8dee8e28d230fb4af8fe4', () => {
    const packet = parsePacket(packets[0])
    assert.equal(packet.packetType, PACKET_ANNOUNCE)
    assert.equal(bytesToHex(packet.destinationHash), '072ec44973a8dee8e28d230fb4af8fe4')
    assert.equal(bytesToHex(packet.packetHash), 'e56755f8b7405b07c12a5c25d7b9b744ca296f7349768b335c78be868530b57d')
    const announce = parseAnnounce(packet)
    assert.ok(announce.valid)
  })
  test('76a93cda889a8c0a88451e02d53fd8b9', () => {
    const packet = parsePacket(packets[1])
    assert.equal(packet.packetType, PACKET_ANNOUNCE)
    assert.equal(bytesToHex(packet.destinationHash), '76a93cda889a8c0a88451e02d53fd8b9')
    assert.equal(bytesToHex(packet.packetHash), '1d17ee4b806f343804567c56ac9d1204e06ef9bc0d1e44b3970f4138a8ef897b')
    const announce = parseAnnounce(packet)
    assert.ok(announce.valid)
  })

  test('7d62e355cc90ec4e79569d33a8ad6c6b', () => {
    const packet = parsePacket(packets[6])
    assert.equal(packet.packetType, PACKET_ANNOUNCE)
    assert.equal(bytesToHex(packet.destinationHash), '7d62e355cc90ec4e79569d33a8ad6c6b')
    assert.equal(bytesToHex(packet.packetHash), '108b781ce8b8029f8335fc4a4b8a295895c3878d36467bb88da7137c88d3c282')
    const announce = parseAnnounce(packet)
    assert.ok(announce.valid)
  })

  test('acd4eef4901f2b7c69e761dc8781ed4c', () => {
    const packet = parsePacket(packets[7])
    assert.equal(packet.packetType, PACKET_ANNOUNCE)
    assert.equal(bytesToHex(packet.destinationHash), 'acd4eef4901f2b7c69e761dc8781ed4c')
    assert.equal(bytesToHex(packet.packetHash), 'b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77')
    const announce = parseAnnounce(packet)
    assert.ok(announce.valid)
  })
})

describe('DATA', () => {
  test('2831d76f1a8035638505c132fe5818c1 (A -> B)', () => {
    const packet = parsePacket(packets[2])
    assert.equal(packet.packetType, PACKET_DATA)
    assert.equal(bytesToHex(packet.packetHash), '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8')

    // it's to Client B
    assert.equal(bytesToHex(packet.destinationHash), '76a93cda889a8c0a88451e02d53fd8b9')
    const identity = recipients[packet.destinationHash]
    assert.ok(identity)

    assert.equal(bytesToHex(packet.packetHash), '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8')

    const [ts, title, content] = msgunpack(messageDecrypt(packet, identity[1], ratchets).slice(80))
    assert.equal(title.length, 0)
    assert.equal(decoder.decode(content), 'hello from A')

    // save for PROOF validation
    sentPackets[packet.packetHash.slice(0, 16)] = { recipientHash: packet.destinationHash, packetHash: packet.packetHash }
  })

  test('d7c0e833f0cbde9f9133cd9e7d508b1a (B -> A)', () => {
    const packet = parsePacket(packets[4])
    assert.equal(packet.packetType, PACKET_DATA)
    assert.equal(bytesToHex(packet.packetHash), 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a')

    // it's to Client A
    assert.equal(bytesToHex(packet.destinationHash), '072ec44973a8dee8e28d230fb4af8fe4')
    const identity = recipients[packet.destinationHash]
    assert.ok(identity)

    assert.equal(bytesToHex(packet.packetHash), 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a')

    const [ts, title, content] = msgunpack(messageDecrypt(packet, identity[1], ratchets).slice(80))
    assert.equal(title.length, 0)
    assert.equal(decoder.decode(content), 'hello from B')

    // save for PROOF validation
    sentPackets[packet.packetHash.slice(0, 16)] = { recipientHash: packet.destinationHash, packetHash: packet.packetHash }
  })
})

describe('LXMF', () => {
  test('2831d76f1a8035638505c132fe5818c1 (A -> B)', () => {
    const packet = parsePacket(packets[2])
    assert.equal(packet.packetType, PACKET_DATA)
    assert.equal(bytesToHex(packet.packetHash), '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8')

    assert.equal(bytesToHex(packet.destinationHash), '76a93cda889a8c0a88451e02d53fd8b9')
    const identity = recipients[packet.destinationHash]
    assert.ok(identity)

    const { sourceHash, signature, timestamp, title, content, fields } = parseLxmf(packet, identity[1], ratchets)

    assert.deepEqual(sourceHash, hexToBytes('072ec44973a8dee8e28d230fb4af8fe4'))
    assert.equal(bytesToHex(signature), '7b9beae3f07ab3255f0c77fe295ddca70b032fd45735252025eb32dcfe9b278a9f1891ef96d2291a9f8289de000ca695d4586c8d1a846100621f01aa73134a00')
    assert.equal(timestamp, 1759383635.953418)
    assert.equal(title, '')
    assert.equal(content, 'hello from A')
    assert.deepEqual(fields, {})
  })

  test('d7c0e833f0cbde9f9133cd9e7d508b1a (A -> B)', () => {
    const packet = parsePacket(packets[4])
    assert.equal(packet.packetType, PACKET_DATA)
    assert.equal(bytesToHex(packet.packetHash), 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a')

    assert.equal(bytesToHex(packet.destinationHash), '072ec44973a8dee8e28d230fb4af8fe4')
    const identity = recipients[packet.destinationHash]
    assert.ok(identity)

    const { sourceHash, signature, timestamp, title, content, fields } = parseLxmf(packet, identity[1], ratchets)

    assert.deepEqual(sourceHash, hexToBytes('76a93cda889a8c0a88451e02d53fd8b9'))
    assert.equal(bytesToHex(signature), '164bd6078866c67d5997ec8871d60125b24b4778be092c7ba6b5a20c3dad7a1c98a0382d4d77771edf93c96d78a668a962804a8009220d5ff3e8e9912718c809')
    assert.equal(timestamp, 1759383650.12609)
    assert.equal(title, '')
    assert.equal(content, 'hello from B')
    assert.deepEqual(fields, {})
  })
})

describe('PROOF', () => {
  test('2831d76f1a8035638505c132fe5818c1 (A -> B)', () => {
    const packet = parsePacket(packets[3])
    assert.equal(packet.packetType, PACKET_PROOF)
    assert.equal(bytesToHex(packet.destinationHash), '2831d76f1a8035638505c132fe5818c1')
    assert.equal(bytesToHex(packet.packetHash), 'c6c8d3a2da7de271b3262ed73f8d07f2d9b665e6dd382c610b2761f3484a6979')

    // lookup DATA packet that we "sent" for recipient & full-hash (only we know that, because we sent it)
    const { recipientHash, packetHash } = sentPackets[packet.destinationHash]
    assert.equal(bytesToHex(packetHash), '2831d76f1a8035638505c132fe5818c1d1d25869a973d35c197d669f0d5074d8')

    // it's to Client B
    assert.equal(bytesToHex(recipientHash), '76a93cda889a8c0a88451e02d53fd8b9')
    const identity = recipients[recipientHash]
    assert.ok(identity)

    const { valid } = parseProof(packet, identity[1], packetHash)
    assert.ok(valid)
  })

  test('d7c0e833f0cbde9f9133cd9e7d508b1a (B -> A)', () => {
    const packet = parsePacket(packets[5])
    assert.equal(packet.packetType, PACKET_PROOF)
    assert.equal(bytesToHex(packet.destinationHash), 'd7c0e833f0cbde9f9133cd9e7d508b1a')
    assert.equal(bytesToHex(packet.packetHash), '3e98d0daf2b23edece8737b0ca348a04d882b1a4800b375259a6b03a1fa3b428')

    // lookup DATA packet that we "sent" for recipient & full-hash (only we know that, because we sent it)
    const { recipientHash, packetHash } = sentPackets[packet.destinationHash]
    assert.equal(bytesToHex(packetHash), 'd7c0e833f0cbde9f9133cd9e7d508b1a61d2c89410e9009e4474b9212ed0370a')

    // it's to Client A
    assert.equal(bytesToHex(recipientHash), '072ec44973a8dee8e28d230fb4af8fe4')
    const identity = recipients[recipientHash]
    assert.ok(identity)

    const { valid } = parseProof(packet, identity[1], packetHash)
    assert.ok(valid)
  })
})
