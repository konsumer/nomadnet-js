import { hexToBytes, bytesToHex } from '../src/index.js'
import { sha256 } from '../src/crypto.js'
import { createHash } from 'crypto'

// Test SHA256 implementation against Node's crypto
const test_data = [hexToBytes('014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308'), new Uint8Array([0x01, 0x02, 0x03]), new Uint8Array([])]

console.log('Testing SHA256 implementation...\n')

for (let i = 0; i < test_data.length; i++) {
  const data = test_data[i]

  // Our implementation
  const our_hash = sha256(data)

  // Node's crypto
  const hash = createHash('sha256')
  hash.update(data)
  const node_hash = new Uint8Array(hash.digest())

  console.log(`Test ${i + 1}:`)
  console.log(`Data length: ${data.length}`)
  console.log(`Our SHA256:  ${bytesToHex(our_hash)}`)
  console.log(`Node SHA256: ${bytesToHex(node_hash)}`)
  console.log(`Match: ${bytesToHex(our_hash) === bytesToHex(node_hash)}`)
  console.log()
}

// Test the specific case from the failing test
console.log('Testing the specific hashable part from the failing test:')
const hashable = hexToBytes('014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308')
console.log('Hashable length:', hashable.length)
console.log('Hashable hex:', bytesToHex(hashable))
console.log('SHA256:', bytesToHex(sha256(hashable)))
console.log('Expected:', 'b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77')
