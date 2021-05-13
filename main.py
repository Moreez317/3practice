import struct

E_SIZE = 8 + 2 + 1 + 4 + 2 + 1
D_SIZE = 2 + 4 + 4 + 4 + 8 + 2
C_SIZE = 4 + 8
B_SIZE = 1 * 4 + 1 + 1
A_SIZE = 4 + 4 + 4 + C_SIZE + E_SIZE + 1 + 8 * 5 + 8 + 2

def parse_e(offset, byte_string):
    e_bytes = byte_string[offset:offset + E_SIZE]
    e_parsed = struct.unpack('qHbIHB', e_bytes)
    e4_bytes = byte_string[e_parsed[4]:e_parsed[4] + e_parsed[3] * 8]
    e4_parsed = struct.unpack('d' * e_parsed[3], e4_bytes)
    return {
        'E1' : e_parsed[0],
        'E2' : e_parsed[1],
        'E3' : e_parsed[2],
        'E4' : list(e4_parsed),
        'E5' : e_parsed[5]
    }

def parse_d(offset, byte_string):
    d_bytes = byte_string[offset:offset + D_SIZE]
    d_parsed = struct.unpack('hfIiqH', d_bytes)
    return {
        'D1' : d_parsed[0],
        'D2' : d_parsed[1],
        'D3' : d_parsed[2],
        'D4' : d_parsed[3],
        'D5' : d_parsed[4],
        'D6' : d_parsed[5]
    }

def parse_c(offset, byte_string):
    c_bytes = byte_string[offset:offset + C_SIZE]
    c_parsed = struct.unpack('Id', c_bytes)
    return {
        'C1' : parse_d(c_parsed[0], byte_string),
        'C2' : c_parsed[1]
    }

def parse_b(offset, byte_string):
    b_bytes = byte_string[offset:offset + B_SIZE]
    b_parsed = struct.unpack('ccccBB', b_bytes)
    return {
        'B1' : list(b_parsed[:3]),
        'B2' : b_parsed[4],
        'B3' : b_parsed[5]
    }

def parse_a(offset, byte_string):
    a12_bytes = byte_string[offset:offset + 12]
    a12_parsed = struct.unpack('IIi', a12_bytes)
    print(a12_parsed)
    a3_parsed = parse_c(offset + 12, byte_string)
    a4_parsed = parse_e(offset + 12 + C_SIZE, byte_string)
    a5678_bytes = byte_string[offset:offset + 12 + C_SIZE + E_SIZE]
    a5678_parsed = ('bQQQQQdh', a5678_bytes)
    a1_bytestring = byte_string[a12_parsed[1]:a12_parsed[1] + a12_parsed[0] * B_SIZE]
    a1_list = [parse_b(addr, a1_bytestring) for addr in a12_parsed[0]]
    return {
        'A1' : a1_list,
        'A2' : a12_parsed[2],
        'A3' : a3_parsed,
        'A4' : a4_parsed,
        'A5' : a5678_parsed[0],
        'A6' : a5678_parsed[1:5],
        'A7' : a5678_parsed[6],
        'A8' : a5678_parsed[7]
    }

def f31(byte_string):
    return parse_a(8, byte_string)

print(f31(b'\xe7CIGX\x00\x00\x00\x02\x00\x00\x00bh\x19\x92\x0e\x00\x00\x00n?\xeel'
b'\xaaB\x19\xb0x7\xb8\x0f\xc7\x113\xec\x00dj\xa6\x00\x00\x00\x02'
b'\x00\x86\xa8\x11G`\xfb\xb1\xa7A_\xc2#?T\x92;\xc3\x9e\xd5\x16\x1eu\x8c'
b'$:\x0b\x85\xf1M\xb3\xaa\x82\xf0\xab\xd5\x1ef\x84\xa4\x90\xeb\xdb\xe9'
b'\xbf\xb5\xa0}I\xa0\xe1\xe0]\xd6jfpfM\xa7aixeJ\xdd;\x96>\xcc\xb1\x95'
b'\xbe\xbb\xb7Kc\xd0l\xf9\x97J|\x08\x87\t\xbe-K\r?\xe1i\xb1\xf2q\x1e\x14?\xb6'
b'\x00N\x0f\x86(\xa0'))