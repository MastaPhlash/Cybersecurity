"""
test_utils.py
Unit tests for utils.py
"""
import unittest
from utils import load_theme, save_theme
import os

class TestUtils(unittest.TestCase):
    def test_theme_persistence(self):
        save_theme('dark')
        self.assertEqual(load_theme(), 'dark')
        save_theme('light')
        self.assertEqual(load_theme(), 'light')
        # Clean up
        if os.path.exists('portscanner.cfg'):
            os.remove('portscanner.cfg')

    def test_theme_file_missing(self):
        # Remove config if exists, should default to 'light'
        if os.path.exists('portscanner.cfg'):
            os.remove('portscanner.cfg')
        self.assertEqual(load_theme(), 'light')

    def test_theme_file_corrupt(self):
        # Write a corrupt config file
        with open('portscanner.cfg', 'w') as f:
            f.write('not a config')
        # Should not raise, should default to 'light'
        self.assertEqual(load_theme(), 'light')
        os.remove('portscanner.cfg')

if __name__ == '__main__':
    unittest.main()
