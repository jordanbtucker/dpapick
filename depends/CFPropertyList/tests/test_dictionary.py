import unittest
from reference import parsed_binary

class DictionaryTest(unittest.TestCase):
    def test_read_dictionary(self):
        self.assertEqual({'key':'value'}, parsed_binary('dictionary'))    

if __name__ == '__main__':
    unittest.main()
