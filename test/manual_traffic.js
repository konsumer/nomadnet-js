// this is a self-contained tester that will read info from test/b client


import { readFile, glob } from 'node:fs/promises'
import * as msgpack from 'msgpackr'

// glob is experimental
process.removeAllListeners('warning');

const hexdump = b => Buffer.from(b).toString('hex').replace(/(\w{2})/g, '$1 ').toUpperCase()

const peersettings = msgpack.unpack(await readFile('test/b/nomad/storage/peersettings'))
const directory = msgpack.unpack(await readFile('test/b/nomad/storage/directory'))
console.log({ peersettings, directory })

const identity = new Uint8Array(await readFile('test/b/nomad/storage/identity'))
console.log('identity', hexdump(identity))

const ratchets = {}
console.log('ratchets: ')
for await (const f of glob('test/b/nomad/storage/lxmf/ratchets/*')) {
  const name = f.replace(/test\/b\/nomad\/storage\/lxmf\/ratchets\/(.+)\.ratchets/g, '$1')
  ratchets[name] = new Uint8Array(await readFile(f))
  console.log('  ', name)
}