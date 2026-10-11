import importlib.util
import pathlib
import struct
import unittest

spec = importlib.util.spec_from_file_location('uf2conv', pathlib.Path(__file__).with_name('uf2conv.py'))
uf2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uf2)

class ConversionTests(unittest.TestCase):
    def test_short_detection(self):
        for size in range(8):
            self.assertFalse(uf2.is_uf2(bytes(size)))
        self.assertFalse(uf2.is_hex(b''))

    def test_truncated_or_invalid_blocks(self):
        valid = uf2.convert_to_uf2(bytes(256))
        for cut in [1, 8, 31, 511]:
            with self.assertRaises(ValueError):
                uf2.convert_from_uf2(valid[:cut])
        for offset, value in [(0,0), (508,0), (16,477)]:
            invalid = bytearray(valid)
            struct.pack_into('<I', invalid, offset, value)
            with self.assertRaises(ValueError):
                uf2.convert_from_uf2(invalid)

    def test_hex_checksum_and_empty_lines(self):
        self.assertEqual(uf2.convert_from_hex_to_uf2('\n:00000001FF\n'), b'')
        for record in [':0000000100', ':0200000400', ':GG000001FF']:
            with self.assertRaises(ValueError):
                uf2.convert_from_hex_to_uf2(record)

if __name__ == '__main__':
    unittest.main()
