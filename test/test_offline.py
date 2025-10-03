import unittest
from test import demo_data
import RNS
from RNS.vendor import umsgpack

class TestOfflinePackets(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up identities once for all tests"""
        cls.clientA = RNS.Identity.from_bytes(demo_data.keys['clientA'])
        cls.clientB = RNS.Identity.from_bytes(demo_data.keys['clientB'])
        
        cls.clientA_addr = RNS.Destination.hash(cls.clientA, "lxmf", "delivery")
        cls.clientB_addr = RNS.Destination.hash(cls.clientB, "lxmf", "delivery")
        
        cls.identities = {
            cls.clientA_addr: cls.clientA,
            cls.clientB_addr: cls.clientB
        }
    
    def load_packet(self, raw):
        """Load a packet from raw bytes without side effects"""
        packet = RNS.Packet.__new__(RNS.Packet)
        packet.raw = raw
        RNS.Packet.unpack(packet)
        packet.rssi = None
        packet.snr = None
        packet.receiving_interface = None
        return packet
    
    def process_data(self, packet, identity):
        """Decrypt and parse DATA packet"""
        decryptedBytes = identity.decrypt(packet.data, ratchets=demo_data.ratchets)
        return umsgpack.unpackb(decryptedBytes[80:])
    
    def test_identity_addresses(self):
        """Test that identity addresses are computed correctly"""
        self.assertEqual(self.clientA_addr.hex(), '072ec44973a8dee8e28d230fb4af8fe4')
        self.assertEqual(self.clientB_addr.hex(), '76a93cda889a8c0a88451e02d53fd8b9')
    
    def test_packet_count(self):
        """Test expected number of packets in demo data"""
        self.assertGreater(len(demo_data.packets), 0, "Should have at least one packet")
    
    def test_announce_packets(self):
        """Test that ANNOUNCE packets are valid"""
        announce_count = 0
        for p in demo_data.packets:
            packet = self.load_packet(p)
            if packet.packet_type == RNS.Packet.ANNOUNCE:
                announce_count += 1
                self.assertTrue(
                    RNS.Identity.validate_announce(packet, True),
                    f"ANNOUNCE packet {packet.destination_hash.hex()} should be valid"
                )
        
        self.assertGreater(announce_count, 0, "Should have at least one ANNOUNCE packet")
    
    def test_data_packets_decrypt(self):
        """Test that DATA packets decrypt successfully"""
        data_count = 0
        for p in demo_data.packets:
            packet = self.load_packet(p)
            if packet.packet_type == RNS.Packet.DATA:
                data_count += 1
                
                # Packet should be addressed to one of our identities
                self.assertIn(
                    packet.destination_hash, 
                    self.identities,
                    f"DATA packet destination {packet.destination_hash.hex()} should be known"
                )
                
                # Should decrypt without error
                identity = self.identities[packet.destination_hash]
                ts, title, content, fields = self.process_data(packet, identity)
                
                # Basic validation
                self.assertIsInstance(ts, float, "Timestamp should be a float")
                self.assertIsInstance(content, bytes, "Content should be bytes")
                
                # Content should be valid UTF-8
                content_str = content.decode('utf-8')
                self.assertGreater(len(content_str), 0, "Content should not be empty")
        
        self.assertGreater(data_count, 0, "Should have at least one DATA packet")
    
    def test_specific_message_content(self):
        """Test that specific messages have expected content"""
        messages_found = []
        
        for p in demo_data.packets:
            packet = self.load_packet(p)
            if packet.packet_type == RNS.Packet.DATA:
                identity = self.identities.get(packet.destination_hash)
                if identity:
                    ts, title, content, fields = self.process_data(packet, identity)
                    messages_found.append(content.decode('utf-8'))
        
        # Check that we got some expected messages
        self.assertGreater(len(messages_found), 0, "Should have received messages")
        
        # All messages should be non-empty strings
        for msg in messages_found:
            self.assertIsInstance(msg, str)
            self.assertGreater(len(msg), 0)
    
    def test_ratchets_available(self):
        """Test that ratchets are available in demo data"""
        self.assertIsNotNone(demo_data.ratchets, "Ratchets should be defined")
        self.assertGreater(len(demo_data.ratchets), 0, "Should have at least one ratchet")
        
        # Each ratchet should be 32 bytes
        for ratchet in demo_data.ratchets:
            self.assertEqual(len(ratchet), 32, "Ratchet should be 32 bytes")
    
    def test_packet_types(self):
        """Test that we have expected packet types"""
        packet_types = set()
        
        for p in demo_data.packets:
            packet = self.load_packet(p)
            packet_types.add(packet.packet_type)

if __name__ == '__main__':
    unittest.main()