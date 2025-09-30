// manually parsing real traffic (between 2 official clients) using real keys

// not all of these may be needed, but here is some crypto/etc utils
import { hexToBytes, bytesToHex, concatBytes } from '@noble/curves/utils.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { cbc } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { unpack, pack } from 'msgpackr'

/*
	// this came from real traffic between 2 clients (4f55a90b & 4ffdfafc)
	- 4f55a90b ANNOUNCEs itself
	- 4ffdfafc ANNOUNCEs itself
	- 4f55a90b sends DATA (message) to 4ffdfafc
	- 4ffdfafc sends PROOF (received-receipt) for message 2cc5ec7b
	- 4ffdfafc sends DATA (message) to 4f55a90b
	- 4f55a90b sends PROOF (received-receipt) for message c0945207
*/
const packets = `21004f55a90bda8fc8b2ff6db3b9b35005f000e0eec6696d6ef606b1919c86dafbf8b10d076c9f33e80319f6f41db0aa17d32a08fa2ed0ab67a5957fe52fcb907a6a1a4e04b1c8682daf78e0d451058d7c4e146ec60bc318e2c0f0d908a584e315310068d9c8125037bc6886277fe78696d3458dce1757ae904f340e1ea479e5d0e3e1b16e7819a9fa21c1cc20b037e8ef283de393fd65e1b04370dfcc3761aae4f5387b42a44399d930dbaa9643c55439665c6a17e7f858e91616f43fd3819680c640f070610192c40e416e6f6e796d6f75732050656572c0
21004ffdfafcd44675dfa6e03393ffdedc8700352b4efa2a28bc3c97cd3405c0ccad16b70ea5b17334c1f7520727103b788a4a489824577f21588530e6f7b85421ac678193d5f749aa54e1e8c970924b4d8c5d6ec60bc318e2c0f0d9086e71fe30530068d9c81c235b81149f324b9f1febec01b5c709cece4426626712acff24ca871eac1431264ad1ff8b5dd999f270a2b092a27d777c6f7834b2873453b327e233f23a33b379826e45f4827128e973eedf66aade31464d94efbb80e4444393e76534d8ce360692c40e416e6f6e796d6f75732050656572c0
00004ffdfafcd44675dfa6e03393ffdedc87007fd42a64baebe5a643afd7175d80e02d42a77b92c2be01dc64a063019de7a5204029544be7545d65ebb88c266065e27cb8fdcf4d2e68416783f7d0620345cd4dacdd8dd0ac27e8ad2d4e198ee33ae71ba40802f2eb201b49cdb389ef8c6e4949bb7ac948613df3f3b686c148d78d91681cf69f9da27b92ba122dca645b79346155bce8a1fa5015e9d6b397645883fb020a0e43a87a4a32a386882ea6b5aa03c7f0d28ee04bb0f354180d8fddc5415b3328a250f05f8a9563bb626a9804e3aedf
03002cc5ec7b99fcd8e4c82f21accbe3421e008c25bb546be1c78c6f78c4017ead9c10b8e81b1de937098c0ef4c380144308c950699fd8a889e029a242225983aef4cf952853b6a1be5df068ad7f30d6fa7c01
00004f55a90bda8fc8b2ff6db3b9b35005f000e5678441c78799543fc642553b72cff136a839258c76a49cd37f40edd5f1f01e68a514f3be0ef894e4959ab3d28d21cfd25fba78378b921b9aff5c225aedcd9db9ea4d084a6d3417f846e175cdec0d5c04ce157fefb13f677bdb8080e56f94bd30370838ce288a42e8eadbfb5066f2198ea401fa7e7e18f20848ab05134750ca9c06dcfc830a78b2ac79d4fc2100df44078ca8e51e124a9c077c889966a4035bd6a74f16701fc3108be29f121f21326a5940918d9d7cd28d9ed2af6facc0e050
0300c094520762dc17144f879fe589e340ad001be96da381b0be4bbb438cda6112b8e095aff8417f8bf65690746b199d3984c7183e66d68764d2e56f99988569594116f7179ffae0c97cb27026c80ae23a280e`
  .split('\n')
  .map((l) => hexToBytes(l))

// these came from nomad identity files of each client
// they are 2 keys each (sign & encrypt)
const identities = {
  '4f55a90bda8fc8b2ff6db3b9b35005f0': {
    sign: hexToBytes('081a5e6bef228982e4b06f3df1b6c1dc7975fa7e27082b6564f5d0a96c644f4d'),
    encrypt: hexToBytes('e47251da287ae3a87db9cbab4707816a2d761f1371399ee1690be7b7ee0cbbb2')
  },
  '4ffdfafcd44675dfa6e03393ffdedc87': {
    sign: hexToBytes('40081d522aa9ad55c776ee552d1f4a4ee1c934b0f23c0c049f3b602e82fd9776'),
    encrypt: hexToBytes('50c9e6e2a903c0a52b746a7869b38f45069cadfe716aabe1392f2e17e49b92a1')
  }
}

// these came from reticulum ratchet files of each client
// they each have a ratchet for themself & the other
// in the original files, they all have 82a772617463686574c420 header at beginning
const ratchets = {
  '4f55a90bda8fc8b2ff6db3b9b35005f0': {
    '4f55a90bda8fc8b2ff6db3b9b35005f0': unpack(hexToBytes('82a772617463686574c4205037bc6886277fe78696d3458dce1757ae904f340e1ea479e5d0e3e1b16e7819a87265636569766564cb41da3671fad48af6')),
    '4ffdfafcd44675dfa6e03393ffdedc87': unpack(hexToBytes('82a772617463686574c420235b81149f324b9f1febec01b5c709cece4426626712acff24ca871eac143126a87265636569766564cb41da3671fe60f6d1'))
  },
  '4ffdfafcd44675dfa6e03393ffdedc87': {
    '4f55a90bda8fc8b2ff6db3b9b35005f0': unpack(hexToBytes('82a772617463686574c4205037bc6886277fe78696d3458dce1757ae904f340e1ea479e5d0e3e1b16e7819a87265636569766564cb41da367204ab922e')),
    '4ffdfafcd44675dfa6e03393ffdedc87': unpack(hexToBytes('82a772617463686574c420235b81149f324b9f1febec01b5c709cece4426626712acff24ca871eac143126a87265636569766564cb41da3671fe5c6a9f'))
  }
}

function decrypt(fromAddress, toAddress, packet) {
    // reticulum sing/encrypt private-keys
    const { sign, encrypt }  = identities[toAddress]

    // ratchet pubkey for fromAddress
    const { ratchet } = ratchets[toAddress][fromAddress]
}



// example usage 4f55a90b sends DATA (message) to 4ffdfafc
// since it's a whole packet, I should be able to get destination from packet
console.log(decrypt('4f55a90bda8fc8b2ff6db3b9b35005f0', '4ffdfafcd44675dfa6e03393ffdedc87', packets[2]))
