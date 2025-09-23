import { describe, test } from 'node:test'
import assert from 'node:assert'
import { hexToBytes } from '@noble/curves/utils.js'

// this was pulled from nomad identity file
// rnid -x -i demo/a/nomad/storage/identity
// id 4b48cec75f96ed134c76cae364820a47
const keyBytes = hexToBytes('308a69c6e147ea856912d2377e56e0c9560ea2f9da0e7743009499b6a262b846ea748b08ea8f473111ff2e63ed24603991da24a40745a9a93f53616a8d35d47c')
const pubKeyEncrypt = keyBytes.slice(0, 32)
const pubKeySignature = keyBytes.slice(32)

describe('Identity', () => {})
