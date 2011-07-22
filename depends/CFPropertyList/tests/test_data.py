import unittest
from reference import parsed_binary

class DataTest(unittest.TestCase):
    def test_read_data_short(self):
        self.assertEqual('data', parsed_binary('data_short'))
        
    def test_read_data_long_1_byte(self):
        self.assertEqual('data' * 4, parsed_binary('data_long_1_byte'))
        
    def test_read_data_long_2_bytes(self):
        self.assertEqual('data' * 128, parsed_binary('data_long_2_bytes'))
        
    def test_read_data_long_4_bytes(self):
        self.assertEqual('data' * 16384, parsed_binary('data_long_4_bytes'))

if __name__ == '__main__':
    unittest.main()

