import unittest
from reference import parsed_binary

class OffsetTest(unittest.TestCase):
    def test_read_offsets_1_byte(self):
        array = parsed_binary('offsets_1_byte')
        self.assertEqual(20, len(array))
        for i in range(20):
            self.assertEqual(str(i), array[i])

    def test_read_offsets_2_bytes(self):
        array = parsed_binary('offsets_2_bytes')
        self.assertEqual(2, len(array))
        prefix = '1234567890' * 30
        self.assertEqual('%s-0' % prefix, array[0])
        self.assertEqual('%s-1' % prefix, array[1])

    def test_read_offsets_4_bytes(self):
        array = parsed_binary('offsets_4_bytes')
        self.assertEqual(220, len(array))
        prefix = '1234567890' * 30
        for i in range(220):
            self.assertEqual('%s-%s' % (prefix, i), array[i])


if __name__ == '__main__':
    unittest.main()
