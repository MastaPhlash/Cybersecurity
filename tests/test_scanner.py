"""
test_scanner.py
Unit tests for scanner.py
"""
import unittest
from scanner import validate_ip, validate_port, is_host_alive, grab_banner, nmap_scan, parse_ports

class TestScanner(unittest.TestCase):
    def test_validate_ip(self):
        self.assertTrue(validate_ip('192.168.1.1'))
        self.assertTrue(validate_ip('8.8.8.8'))
        self.assertFalse(validate_ip('999.999.999.999'))
        self.assertFalse(validate_ip('abc.def.ghi.jkl'))

    def test_validate_port(self):
        self.assertTrue(validate_port('22'))
        self.assertTrue(validate_port('65535'))
        self.assertFalse(validate_port('0'))  # Port 0 is not valid
        self.assertFalse(validate_port('70000'))
        self.assertFalse(validate_port('notaport'))

class TestScannerAdvanced(unittest.TestCase):
    def test_is_host_alive_localhost(self):
        self.assertTrue(is_host_alive('127.0.0.1'))

    def test_is_host_alive_invalid(self):
        self.assertFalse(is_host_alive('203.0.113.254'))

    def test_grab_banner_closed_port(self):
        self.assertIsNone(grab_banner('127.0.0.1', 1, 0.5))

    def test_grab_banner_open_port(self):
        result = grab_banner('127.0.0.1', 22, 0.5)
        self.assertTrue(result is None or isinstance(result, str))

class TestNmapScan(unittest.TestCase):
    def test_nmap_scan_not_installed(self):
        import shutil
        orig_which = shutil.which
        shutil.which = lambda x: None
        self.assertIsNone(nmap_scan('127.0.0.1'))
        shutil.which = orig_which

    def test_nmap_scan_localhost(self):
        import shutil
        if shutil.which('nmap'):
            result = nmap_scan('127.0.0.1', '22,80', '-sS')
            self.assertIsInstance(result, str)
            self.assertIn('127.0.0.1', result)
        else:
            self.skipTest('Nmap not installed')

class TestParsePorts(unittest.TestCase):
    def test_single_ports(self):
        self.assertEqual(parse_ports('22,80,443'), [22, 80, 443])
    def test_range(self):
        self.assertEqual(parse_ports('20-22'), [20, 21, 22])
    def test_mixed(self):
        self.assertEqual(parse_ports('20-22,80,443'), [20, 21, 22, 80, 443])
    def test_invalid(self):
        self.assertIsNone(parse_ports('0,70000'))  # Port 0 and 70000 are invalid
        self.assertIsNone(parse_ports('abc'))
    def test_duplicates(self):
        self.assertEqual(parse_ports('22,22,22'), [22])
    def test_spaces(self):
        self.assertEqual(parse_ports(' 22 , 80 , 443 '), [22, 80, 443])
    def test_empty_string(self):
        self.assertEqual(parse_ports(''), [])
    def test_overlapping_ranges(self):
        self.assertEqual(parse_ports('20-22,21,22'), [20, 21, 22])
    def test_reversed_range(self):
        self.assertIsNone(parse_ports('22-20'))
    def test_large_valid_range(self):
        ports = parse_ports('1-1024')
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 1024)
        self.assertEqual(len(ports), 1024)

if __name__ == '__main__':
    unittest.main()
