import { describe, test } from 'node:test'
import assert from 'node:assert'
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { unpackReticulum, unserializeIdentity, PACKET_ANNOUNCE } from '../src/index.js'

// this is real traffic
const packets = `2100848ee1c5fa95580b9801e1932590e3cb00234ccdf2fe2dc18713ae73b87754c56c3446a05e802d4c5f97e66daec391fd602a3e0b113f0782f7a2df6acbf8367289f76a33ba3cb0842f2bb9f379d39ce7fc6ec60bc318e2c0f0d9084f9c92c21d0068d01afa909f2cf34adec012c9f2114753a601b176553958d79850c2ebc13c587e7ae53d351d7b69e0c6a299381fe7f231c0c6f06cfdec7cabd847db1cbb352d76b228a3242986b4137098c02c3682beb6a5c5b9639a7f9f20d8fe7107638d33cceea00092c40e416e6f6e796d6f75732050656572c0
21004e6485cd2710efe20cc558be99b089040024b04bfbfadd40482e6d2ba52d621889416c272066b580fa942b29a54793492ee3af2a772259b59ac1213cfdd5570e2221db611f85b8c1e23343c4521490a4fe6ec60bc318e2c0f0d90809b1b7545e0068d3b9d052228dce488bb49e85f6d6f59f5544651273a921fa11ca9209e28839aef49958402b6fd69e3f57a10cb9f096bffe35e5f4a738c93cb6af175979b4692c26593667303c3134aa6ae0443bda06d712bd4355c2e22bd28a4b2c450690699b56280792c40e416e6f6e796d6f75732050656572c0
00004e6485cd2710efe20cc558be99b0890400ff9c829b7f479da1c84e257a4a75c298b2d4eea564e0e930066ad083c192fb582a2c6ee4b5017f487f201d471e58a64be0f7f97b1a0b1011d8182d7d70d718f019d3c1ccddac6a795986116e89486d93f828a606278c7988e1fd0ab1bd004be0e127a1e1a3ccfa3c58f4634e0db773db3df9978f6b984015f57bb17d252d9d4078623a1dde256c009515e5f7d788e02f678b03149fb8f59ab4140c4df76acde628797670148b9b9a7f5990c769414bdb81f7cf5e3f32c1ca4723d1a540b84800
0300124d06f81c774986fb46c4d955154ef000661b255f0f83d33bcf2d7f270e9a2db2c85a707007a242b16beee6a8552430b39b696040d83481c37a78eebe121e978ce2f889e8c986141cf4ac989a4458920f
00001c23b37646e2550b5f1a1626b6bccc6b004fcc1689e3ea6126564d33412394b6edb9bdf051d77d3179d248f35c3fb957157a2ba824082a733326bdb97a7d1fa8ae868a2844b51ee873aeacb51bf9342d336af0e101dd3fdf9c10e748da1b6dd3bb9d6083a683a210db77a5d65c08c5d2eb7b55477b80aede5b8f154756ceb1f53997e9285268add6ce9fea0a6a91832b3e0f7b61dc0e92dfe533266c20e1f8f1b7849212cc405e587476ae142655eb9a3211804761b5818d32035f3b086294d8ccd2b500b23b621fb99d7106a67f79eec3
0300211b5d214ffd31abf3c6a66e73d15ef000ef686fda50838caac92228b79b204b6f0b84dde526bf12226320b892f60cd2aa8b6b9cef854a3ec15ecb2e11fecad6787317daa90393656c5faf2eb64cb52c01`
  .split('\n')
  .map((l) => hexToBytes(l))

for (const p of packets) {
  const packet = unpackReticulum(p)
  console.log(packet.packetType)
}

// this was pulled from nomad identity file
// rnid -x -i demo/a/nomad/storage/identity
// id 4b48cec75f96ed134c76cae364820a47
const { encPriv, sigPriv } = unserializeIdentity('308a69c6e147ea856912d2377e56e0c9560ea2f9da0e7743009499b6a262b846ea748b08ea8f473111ff2e63ed24603991da24a40745a9a93f53616a8d35d47c')

let packet

// describe('Packet', () => {
//   test('unpackReticulum', () => {
//     packet = unpackReticulum(packets[0])
//     assert.ok(packet)

//     // is it an announce?
//     assert.equal(packet.packetType, PACKET_ANNOUNCE)
//   })

//   test('verifyAnnounce', () => {
//     // verify and get some data
//     const a = verifyAnnounce(packet)
//     assert.ok(a.verified)
//     assert.equal(a.peerName, 'Anonymous Peer')
//   })

//   test('buildAnnounce', () => {
//     const p = buildAnnounce({ encPriv, sigPriv, appName: 'tester', peerName: 'test peer' })
//     assert.ok(p.packet)
//     const pk = unpackReticulum(p.packet)

//     const a = verifyAnnounce(pk)
//     assert.ok(a.verified)
//     assert.equal(a.peerName, 'test peer')
//   })
// })
