import { describe, test } from 'node:test'
import assert from 'node:assert'
import { readFile } from 'node:fs/promises'

import { parseReticulum } from '../src/index.js'

const packetAnnounce = await readFile('test/packets/announce.bin')

describe('Packets', () => {
  test('announce', () => {
    const msg = parseReticulum(packetAnnounce)
  })
})
