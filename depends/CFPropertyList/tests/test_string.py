import unittest
from reference import parsed_binary

class StringTest(unittest.TestCase):
    def test_read_array(self):
        self.assertEqual(["object"], parsed_binary('array'))

    def test_read_string_ascii_short(self):
        self.assertEqual('data', parsed_binary('string_ascii_short'))

    def test_read_string_ascii_long(self):
        self.assertEqual('data' * 4, parsed_binary('string_ascii_long'))

    def test_read_string_utf8_short(self):
        string = 'UTF-8 \xe2\x98\xbc'
        self.assertEqual(string, parsed_binary('string_utf8_short'))

    def test_read_string_utf8_long(self):
        string = 'long UTF-8 data with a 4-byte glyph \xf0\x90\x84\x82'
        self.assertEqual(string, parsed_binary('string_utf8_long'))

if __name__ == '__main__':
    unittest.main()
