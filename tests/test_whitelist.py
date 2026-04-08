import os
import sys
import unittest
import ipaddress

# Adjust sys.path to find src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from attack_manager import AttackStateManager
import attack_manager
import constants

class TestWhitelistPersistence(unittest.TestCase):
    def setUp(self):
        # Usa um arquivo temporário para não sujar o real
        self.test_file = os.path.join(os.getcwd(), "tmp_whitelist.txt")
        constants.WHITELIST_FILE = self.test_file
        attack_manager.WHITELIST_FILE = self.test_file
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        self.manager = AttackStateManager()

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_sync_ips_and_networks(self):
        # 1. Adiciona um IP exato
        ip_exact = "1.2.3.4"
        self.manager.add_to_whitelist(ip_exact)
        
        # 2. Adiciona uma rede
        network = "192.168.1.0/24"
        self.manager.add_to_whitelist(network)
        
        # Verifica estado inicial
        self.assertTrue(self.manager.is_whitelisted(ip_exact))
        self.assertTrue(self.manager.is_whitelisted("192.168.1.50"))
        self.assertIn(ip_exact, self.manager._whitelist_ips)
        
        # 3. Simula Load (Reinício do sistema)
        new_manager = AttackStateManager()
        
        # VERIFICAÇÃO CRUCIAL: O IP exato deve ter sobrevivido e estar em AMBAS as estruturas
        self.assertTrue(new_manager.is_whitelisted(ip_exact), "IP exato deve persistir")
        self.assertTrue(new_manager.is_whitelisted("192.168.1.50"), "Rede deve persistir")
        self.assertIn(ip_exact, new_manager._whitelist_ips, "IP exato deve estar no cache de busca rápida")
        
        # Verifica se o IP exato está na lista principal de redes (o que garante o próximo SAVE)
        found_as_net = any(str(net.network_address) == ip_exact for net in new_manager._whitelist if net.num_addresses == 1)
        self.assertTrue(found_as_net, "IP exato deve estar na lista principal _whitelist")

    def test_removal(self):
        ip = "10.0.0.1"
        self.manager.add_to_whitelist(ip)
        self.assertIn(ip, self.manager._whitelist_ips)
        
        self.manager.remove_from_whitelist(ip)
        self.assertNotIn(ip, self.manager._whitelist_ips)
        self.assertFalse(self.manager.is_whitelisted(ip))

if __name__ == "__main__":
    unittest.main()
