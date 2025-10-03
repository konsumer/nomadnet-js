# Unit-tests for Identity-related functions (for comparison with javascript)

import unittest
from test import demo_data
import RNS
from RNS.vendor import umsgpack

class TestMessage(unittest.TestCase):
  def test_unpack(self):
    # this comes from messages.test.js
    packet_bytes = bytes.fromhex("0000072ec44973a8dee8e28d230fb4af8fe4000e5a79a9aa06ef358e7a0ae8a316e354856f251edbe5059b9ef64844b0c60b12e98056dcbccb9fbc63853a8c49ec8a583cb9f3bf8691624c74e856ee3d13bf844ac471a3b24e12094e0374e31c1a18cf8f614f20e8ca5e94b0b0e6fd1c3a4de2ae99f77e065cb24f4a9588cc8231953a02583f217f4bc48da34920e6a622520ebc07bd870c77e64443a95315367b20cf51ac11a2c6fb6402102a462eda014cdb2670219860679d8b4149d639c29c27f8734eac4afcb47b8f60e734343dea6d8a53c77be20b80176d3a3ea7b3c9f58398aca4a3467ccf5cbedd4af57ef41b38ab")
    destination_hash = packet_bytes[2:18]
    data = packet_bytes[19:]
    identity_a = RNS.Identity.from_bytes(demo_data.keys['clientA'])
    decrypted = identity_a.decrypt(data, ratchets=demo_data.ratchets)
    
    # Skip 80 byte header and unpack
    message_data = umsgpack.unpackb(decrypted[80:])
    timestamp, title, content, fields = message_data
    self.assertEqual(title.decode(), '')
    self.assertEqual(content.decode(), 'Hello from Javascript!')

if __name__ == '__main__':
    unittest.main()