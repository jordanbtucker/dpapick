import unittest
from reference import parsed_binary

class RealTest(unittest.TestCase):
    def test_read_float(self):
        self.assertEqual(1.5, parsed_binary('real_float'))

    def test_read_double(self):
        self.assertEqual(1.5, parsed_binary('real_double'))

if __name__ == '__main__':
    unittest.main()
