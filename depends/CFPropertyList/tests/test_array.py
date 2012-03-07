import unittest
from reference import parsed_binary

class ArrayTest(unittest.TestCase):
    def test_read_array(self):
        self.assertEqual(["object"], parsed_binary('array'))

if __name__ == '__main__':
    unittest.main()
