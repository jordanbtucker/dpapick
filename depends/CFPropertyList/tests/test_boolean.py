import unittest
from reference import parsed_binary

class BooleanTest(unittest.TestCase):
    def test_read_true(self):
        self.assertEqual(True, parsed_binary('boolean_true'))
        
    def test_read_false(self):
        self.assertEqual(False, parsed_binary('boolean_false'))

if __name__ == '__main__':
    unittest.main()
