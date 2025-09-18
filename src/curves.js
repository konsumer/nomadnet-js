/**
 * Minimal Curve25519 and Ed25519 implementation
 * Zero-dependency elliptic curve operations for X25519 and Ed25519
 * Based on RFC 7748 (X25519) and RFC 8032 (Ed25519)
 */

// Prime for Curve25519: 2^255 - 19
const P = 2n ** 255n - 19n

// Ed25519 parameters
const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n
const ED25519_A = -1n

/**
 * Modular arithmetic helpers
 */
function mod(a, m = P) {
  const result = a % m
  return result >= 0n ? result : result + m
}

function modInverse(a, m = P) {
  // Extended Euclidean Algorithm
  let old_r = a, r = m
  let old_s = 1n, s = 0n

  while (r !== 0n) {
    const quotient = old_r / r
    ;[old_r, r] = [r, old_r - quotient * r]
    ;[old_s, s] = [s, old_s - quotient * s]
  }

  return mod(old_s, m)
}

function modPow(base, exp, mod) {
  let result = 1n
  base = base % mod
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod
    }
    exp = exp >> 1n
    base = (base * base) % mod
  }
  return result
}

/**
 * Convert bytes to big integer (little-endian)
 */
function bytesToBigInt(bytes) {
  let result = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = result * 256n + BigInt(bytes[i])
  }
  return result
}

/**
 * Convert big integer to bytes (little-endian, 32 bytes)
 */
function bigIntToBytes(num) {
  const bytes = new Uint8Array(32)
  let n = num
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xFFn)
    n >>= 8n
  }
  return bytes
}

/**
 * Clamp scalar for Curve25519
 */
function clampScalar(scalar) {
  const clamped = new Uint8Array(scalar)
  clamped[0] &= 248
  clamped[31] &= 127
  clamped[31] |= 64
  return clamped
}

/**
 * Montgomery ladder for X25519 scalar multiplication
 */
function montgomeryLadder(scalar, u) {
  const x1 = u
  let x2 = 1n, z2 = 0n
  let x3 = u, z3 = 1n

  const scalarBits = bytesToBigInt(scalar)

  for (let i = 254; i >= 0; i--) {
    const bit = (scalarBits >> BigInt(i)) & 1n
    const swap = bit

    // Conditional swap
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2]
    }

    const A = mod(x2 + z2)
    const AA = mod(A * A)
    const B = mod(x2 - z2)
    const BB = mod(B * B)
    const E = mod(AA - BB)
    const C = mod(x3 + z3)
    const D = mod(x3 - z3)
    const DA = mod(D * A)
    const CB = mod(C * B)

    x3 = mod((DA + CB) * (DA + CB))
    z3 = mod(x1 * (DA - CB) * (DA - CB))
    x2 = mod(AA * BB)
    z2 = mod(E * (AA + mod(121665n * E)))

    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2]
    }
  }

  return mod(x2 * modInverse(z2))
}

/**
 * Derive X25519 public key from private key
 */
export function deriveX25519PublicKey(privateKey) {
  const clamped = clampScalar(privateKey)
  const scalar = bytesToBigInt(clamped)
  const basePoint = 9n

  const publicKeyBigInt = montgomeryLadder(clamped, basePoint)
  return bigIntToBytes(publicKeyBigInt)
}

/**
 * Edwards curve point operations for Ed25519
 */
class EdwardsPoint {
  constructor(x, y, z = 1n, t = null) {
    this.x = x
    this.y = y
    this.z = z
    this.t = t || mod(x * y * modInverse(z))
  }

  static fromBytes(bytes) {
    const y = bytesToBigInt(bytes) & ((1n << 255n) - 1n)
    const sign = (bytesToBigInt(bytes) >> 255n) & 1n

    // Recover x coordinate
    const y2 = mod(y * y)
    const u = mod(y2 - 1n)
    const v = mod(ED25519_D * y2 + 1n)

    let x = mod(u * modInverse(v))
    x = modPow(x, (P + 3n) / 8n, P)

    if (mod(v * x * x) !== mod(u)) {
      x = mod(x * modPow(2n, (P - 1n) / 4n, P))
    }

    if (x % 2n !== sign) {
      x = P - x
    }

    return new EdwardsPoint(x, y)
  }

  add(other) {
    const A = mod(this.z * other.z)
    const B = mod(A * A)
    const C = mod(this.x * other.x)
    const D = mod(this.y * other.y)
    const E = mod(C * D * ED25519_D)
    const F = mod(B - E)
    const G = mod(B + E)

    const x3 = mod(A * F * ((this.x + this.y) * (other.x + other.y) - C - D))
    const y3 = mod(A * G * (D - ED25519_A * C))
    const z3 = mod(F * G)

    return new EdwardsPoint(x3, y3, z3)
  }

  double() {
    return this.add(this)
  }

  multiply(scalar) {
    let result = EdwardsPoint.identity()
    let base = this

    while (scalar > 0n) {
      if (scalar & 1n) {
        result = result.add(base)
      }
      base = base.double()
      scalar >>= 1n
    }

    return result
  }

  toBytes() {
    const invZ = modInverse(this.z)
    const x = mod(this.x * invZ)
    const y = mod(this.y * invZ)

    const bytes = bigIntToBytes(y)
    if (x & 1n) {
      bytes[31] |= 0x80
    }

    return bytes
  }

  static identity() {
    return new EdwardsPoint(0n, 1n, 1n, 0n)
  }

  static basePoint() {
    // Ed25519 base point
    const y = 0x5866666666666666666666666666666666666666666666666666666666666666n
    const x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51An
    return new EdwardsPoint(x, y)
  }
}

/**
 * Derive Ed25519 public key from private key
 */
export async function deriveEd25519PublicKey(privateKey) {
  // Hash the private key with SHA-512
  const hash = await crypto.subtle.digest('SHA-512', privateKey)
  const hashBytes = new Uint8Array(hash)

  // Clamp the first 32 bytes
  hashBytes[0] &= 248
  hashBytes[31] &= 127
  hashBytes[31] |= 64

  // Convert to scalar
  const scalar = bytesToBigInt(hashBytes.slice(0, 32))

  // Multiply base point by scalar
  const basePoint = EdwardsPoint.basePoint()
  const publicPoint = basePoint.multiply(scalar)

  return publicPoint.toBytes()
}