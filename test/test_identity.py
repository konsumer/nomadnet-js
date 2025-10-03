# Unit-tests for Identity-related functions (for comparison with javascript)

import unittest
from test import demo_data
import RNS

clientA = RNS.Identity.from_bytes(demo_data.keys['clientA'])
clientB = RNS.Identity.from_bytes(demo_data.keys['clientB'])
clientA_addr = RNS.Destination.hash(clientA, "lxmf", "delivery")
clientB_addr = RNS.Destination.hash(clientB, "lxmf", "delivery")

class TestIdentity(unittest.TestCase):
	# test some pre-made identites for known-values to make sure keys are correct
	def test_clientA(self):
		encPriv = clientA.get_private_key()[0:32]
		encPub = clientA.get_public_key()[0:32]
		sigPriv = clientA.get_private_key()[32:]
		sigPub = clientA.get_public_key()[32:]
		self.assertEqual(clientA_addr.hex(), '072ec44973a8dee8e28d230fb4af8fe4')
		self.assertEqual(encPriv.hex(), '205131cb9672eaec8a582e8e018307f2428c4aac5e383f12e94939e672b93167')
		self.assertEqual(encPub.hex(), 'a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738')
		self.assertEqual(sigPriv.hex(), '7763c7398d0b9cb6ef1369d023d8af10b85d80f6579c55a6f528953265c15313')
		self.assertEqual(sigPub.hex(), 'da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece')

	def test_clientB(self):
		encPriv = clientB.get_private_key()[0:32]
		encPub = clientB.get_public_key()[0:32]
		sigPriv = clientB.get_private_key()[32:]
		sigPub = clientB.get_public_key()[32:]
		self.assertEqual(clientB_addr.hex(), '76a93cda889a8c0a88451e02d53fd8b9')
		self.assertEqual(encPriv.hex(), 'e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759')
		self.assertEqual(encPub.hex(), '71f199f04d3589ca083c66ff91baed628ee19517ef68eb209827df3a6785cf5b')
		self.assertEqual(sigPriv.hex(), '142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd')
		self.assertEqual(sigPub.hex(), '0af43fb0e168176370828fcdc199e5ae2b208b57cf65179ffa8f25733d9d40bc')

if __name__ == '__main__':
    unittest.main()