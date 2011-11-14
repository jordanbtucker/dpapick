import unittest
import sys
sys.path.append('..')
import CFPropertyList

class FileTest(unittest.TestCase):
    def test_file(self):
        with open('reference/array.plist','r') as f:
            plist = CFPropertyList.CFPropertyList(f)
            plist.load()
            values = CFPropertyList.native_types(plist.value)
            self.assertEqual(["object"], values)

if __name__ == '__main__':
    unittest.main()
