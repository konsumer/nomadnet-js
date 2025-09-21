import * as msgpack from 'msgpackr'
import { ed25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import { randomBytes } from '@noble/hashes/utils'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Constants from Reticulum
export const TRUNCATED_HASHLENGTH = 16
export const HASHLENGTH = 32
export const SIGLENGTH = 64

export const MTU = 500
export const MAX_QUEUED_ANNOUNCES = 16384
export const QUEUED_ANNOUNCE_LIFE = 60 * 60 * 24

// HDLC constants
export const HDLC_FLAG = 0x7e
export const HDLC_ESC = 0x7d
export const HDLC_ESC_MASK = 0x20

// Reticulum constants
export const HEADER_MINSIZE = 2 + 1 + 1
export const HEADER_MAXSIZE = 2 + 2 + 1 + 1
export const IFAC_MIN_SIZE = 1
export const IFAC_OVERHEAD = 1 + 1 + HASHLENGTH // Identity indentifier, IFAC flag, IFAC value

// Packet types
export const PACKET_DATA = 0x00
export const PACKET_ANNOUNCE = 0x01
export const PACKET_LINKREQUEST = 0x02
export const PACKET_PROOF = 0x03

// Header types
export const HEADER_1 = 0x00
export const HEADER_2 = 0x01

// Context types
export const CONTEXT_NONE = 0x00
export const CONTEXT_RESOURCE = 0x01
export const CONTEXT_RESOURCE_ADV = 0x02
export const CONTEXT_RESOURCE_REQ = 0x03
export const CONTEXT_RESOURCE_HMU = 0x04
export const CONTEXT_RESOURCE_PRF = 0x05
export const CONTEXT_RESOURCE_ICL = 0x06
export const CONTEXT_RESOURCE_RCL = 0x07
export const CONTEXT_CACHE_REQUEST = 0x08
export const CONTEXT_REQUEST = 0x09
export const CONTEXT_RESPONSE = 0x0a
export const CONTEXT_PATH_RESPONSE = 0x0b
export const CONTEXT_COMMAND = 0x0c
export const CONTEXT_COMMAND_STATUS = 0x0d
export const CONTEXT_CHANNEL = 0x0e
export const CONTEXT_KEEPALIVE = 0x0f

// Destination types
export const DESTINATION_SINGLE = 0x00
export const DESTINATION_GROUP = 0x01
export const DESTINATION_PLAIN = 0x02
export const DESTINATION_LINK = 0x03

// Packet flags
export const FLAG_SPLIT = 0x01
export const FLAG_TRANSPORT = 0x02

// Cryptographic constants used in Reticulum
const reticulumHkdfSalt = new Uint8Array([0xd3, 0x49, 0xf6, 0xd6, 0xe7, 0x89, 0xe6, 0x4a, 0xd4, 0xd3, 0x8f, 0x80, 0xea, 0x56, 0xed, 0x54, 0xde, 0x31, 0x84, 0xc1, 0xae, 0xab, 0xd8, 0x8c, 0x82, 0xc8, 0xda, 0xd5, 0xf1, 0x18, 0x0b, 0xa3])
const reticulumHkdfInfo = encoder.encode('Reticulum/Expand')
