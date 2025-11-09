import { hexToBytes, bytesToHex } from '../src/index.js'
import { sha256 } from '../src/crypto.js'

// The problematic packet
const packet_hex = '71014acdf8ba30fbafe1cddf04857b86422aacd4eef4901f2b7c69e761dc8781ed4c001832c9c605a6806c6d00a691a80acea4f22269e4b2cfdae1ef66f4a2c75edb2a2ec0c6d29518b7f80c7b9b4ff47eb19c51585dd7154adc5869659665519b72916ec60bc318e2c0f0d90830015a7288f64c8ec70d8784690c0b19cf62cda4a679d738b3905b490163b0b7fb0e9cae68790126071531a43e557b5d0d6c6476914c0535e602ce20cc77b727bd03270a8e84b1111030dff13d40d6c929561b1729d4e5fb2130d4f7d35ee3f1b116122bdb0a656f4308'
const packet = hexToBytes(packet_hex)

console.log('=== PACKET STRUCTURE ANALYSIS ===\n')

// Analyze header byte
const header = packet[0]
console.log('Header byte: 0x' + header.toString(16).padStart(2, '0') + ' = 0b' + header.toString(2).padStart(8, '0'))
console.log('  Header type (bits 7-6):', (header >> 6) & 0b11)
console.log('  Context flag (bit 5):', (header >> 5) & 0b1)
console.log('  Transport type (bit 4):', (header >> 4) & 0b1)
console.log('  Destination type (bits 3-2):', (header >> 2) & 0b11)
console.log('  Packet type (bits 1-0):', header & 0b11)

// Check if this is an ANNOUNCE packet with header_type = 1
if (((header >> 6) & 0b11) === 1) {
  console.log('\nThis is a packet with header_type = 1 (has transport ID)')
  console.log('Transport ID byte: 0x' + packet[1].toString(16).padStart(2, '0'))
}

console.log('\n=== HASH CALCULATION ===\n')

// Test different hash calculation methods based on header_type
const header_type = (header >> 6) & 0b11

console.log('Method 1: Original Python implementation (ignore header_type)')
const hashable1 = new Uint8Array(1 + packet.length - 2)
hashable1[0] = packet[0] & 0b00001111
hashable1.set(packet.slice(2), 1)
const hash1 = sha256(hashable1)
console.log('  Hashable length:', hashable1.length)
console.log('  Hash:', bytesToHex(hash1))

console.log('\nMethod 2: Skip transport ID if header_type = 1')
let skip_bytes = 2
if (header_type === 1) {
  skip_bytes = 3  // Skip header + transport ID + hops
}
const hashable2 = new Uint8Array(1 + packet.length - skip_bytes)
hashable2[0] = packet[0] & 0b00001111
hashable2.set(packet.slice(skip_bytes), 1)
const hash2 = sha256(hashable2)
console.log('  Skip bytes:', skip_bytes)
console.log('  Hashable length:', hashable2.length)
console.log('  Hash:', bytesToHex(hash2))

console.log('\nMethod 3: Include transport ID in hash if header_type = 1')
const hashable3 = new Uint8Array(2 + packet.length - 2)
hashable3[0] = packet[0] & 0b00001111
if (header_type === 1) {
  hashable3[1] = packet[1]  // transport ID
  hashable3.set(packet.slice(2), 2)
} else {
  hashable3.set(packet.slice(2), 1)
}
const hash3 = sha256(hashable3)
console.log('  Hashable length:', hashable3.length)
console.log('  Hash:', bytesToHex(hash3))

console.log('\n=== COMPARISON ===\n')
console.log('Expected hash: b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77')
console.log('Method 1 hash:', bytesToHex(hash1))
console.log('Method 2 hash:', bytesToHex(hash2))
console.log('Method 3 hash:', bytesToHex(hash3))

// Let's also check what happens if we include the header type in the hash
console.log('\n=== ADDITIONAL TESTS ===\n')

console.log('Method 4: Include full header byte')
const hashable4 = packet.slice(0)  // Full packet
const hash4 = sha256(hashable4)
console.log('  Hash:', bytesToHex(hash4))

console.log('\nMethod 5: Just check if expected hash is SHA256 of something obvious')
// Try to reverse engineer what might produce the expected hash
const expected = 'b04b846ba727d26ea2a0911b37a2c18460d975fe6816f3718f4953b8d1a6ef77'
console.log('  Expected hash:', expected)

// Check packet structure more carefully
console.log('\n=== PACKET BYTES ===\n')
console.log('Position 0 (header):', '0x' + packet[0].toString(16).padStart(2, '0'))
console.log('Position 1 (transport ID):', '0x' + packet[1].toString(16).padStart(2, '0'))
console.log('Position 2 (hops):', '0x' + packet[2].toString(16).padStart(2, '0'))
console.log('Destination hash (next 16 bytes):', bytesToHex(packet.slice(3, 19)))
