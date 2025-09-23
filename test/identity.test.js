import { describe, test } from 'node:test'
import assert from 'node:assert'
import { hexToBytes } from '@noble/curves/utils.js'

import { unserializeIdentity } from '../src/index.js'

// this was pulled from nomad identity file
// rnid -x -i demo/a/nomad/storage/identity
const { encPriv, sigPriv } = unserializeIdentity('308a69c6e147ea856912d2377e56e0c9560ea2f9da0e7743009499b6a262b846ea748b08ea8f473111ff2e63ed24603991da24a40745a9a93f53616a8d35d47c')

describe('Identity', () => {})
