import { get_message_id, hexToBytes, bytesToHex } from '../src/index.js'

// Test packet from the failing test
const packet = hexToBytes('71014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308')

console.log('Packet bytes:', bytesToHex(packet))
console.log('Packet length:', packet.length)
console.log('First byte:', packet[0], '0x' + packet[0].toString(16), '0b' + packet[0].toString(2).padStart(8, '0'))

// Extract the parts according to get_message_id
const header_type = (packet[0] >> 6) & 0b11
console.log('Header type:', header_type)

const hashable_first = packet[0] & 0b00001111
console.log('First byte & 0b00001111:', hashable_first, '0x' + hashable_first.toString(16), '0b' + hashable_first.toString(2).padStart(8, '0'))

console.log('Bytes to skip:', 2)
console.log('Rest of packet starts at byte 2, length:', packet.length - 2)

// Build hashable part manually
const hashable_part = new Uint8Array(1 + packet.length - 2)
hashable_part[0] = packet[0] & 0b00001111
hashable_part.set(packet.slice(2), 1)

console.log('\nHashable part:')
console.log('First byte:', hashable_part[0], '0x' + hashable_part[0].toString(16))
console.log('Total length:', hashable_part.length)
console.log('Full hashable:', bytesToHex(hashable_part))

// Calculate the hash
const message_id = get_message_id(packet)
console.log('\nCalculated message_id:', bytesToHex(message_id))
console.log('Expected packet_hash:', 'b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77')

// Let's also check what Python would hash
console.log('\nFor Python comparison:')
console.log('hashable_part = bytes([0x' + hashable_part[0].toString(16) + ']) + packet[2:]')
console.log('This should hash to: b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77')
