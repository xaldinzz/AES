
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,
    0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,
    0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,
    0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,
    0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,
    0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,
    0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,
    0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,
    0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i

RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def xtime(value):
    value <<= 1
    if value & 0x100:
        value ^= 0x11b
    return value & 0xff


def multiply(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def key_expansion(key):
    if len(key) != 16:
        raise ValueError("AES-128 membutuhkan key tepat 16 byte.")

    words = [list(key[i:i+4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = words[i-1][:]

        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]

        words.append([
            words[i-4][j] ^ temp[j] for j in range(4)
        ])

    return [
        sum(words[4*r:4*r+4], [])
        for r in range(11)
    ]


def add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    out = state[:]
    for row in range(1, 4):
        values = [state[row + 4*col] for col in range(4)]
        values = values[row:] + values[:row]
        for col in range(4):
            out[row + 4*col] = values[col]
    return out


def inv_shift_rows(state):
    out = state[:]
    for row in range(1, 4):
        values = [state[row + 4*col] for col in range(4)]
        values = values[-row:] + values[:-row]
        for col in range(4):
            out[row + 4*col] = values[col]
    return out


def mix_columns(state):
    out = state[:]
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i+4]
        out[i]   = multiply(a0,2) ^ multiply(a1,3) ^ a2 ^ a3
        out[i+1] = a0 ^ multiply(a1,2) ^ multiply(a2,3) ^ a3
        out[i+2] = a0 ^ a1 ^ multiply(a2,2) ^ multiply(a3,3)
        out[i+3] = multiply(a0,3) ^ a1 ^ a2 ^ multiply(a3,2)
    return out


def inv_mix_columns(state):
    out = state[:]
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i+4]
        out[i]   = multiply(a0,14) ^ multiply(a1,11) ^ multiply(a2,13) ^ multiply(a3,9)
        out[i+1] = multiply(a0,9) ^ multiply(a1,14) ^ multiply(a2,11) ^ multiply(a3,13)
        out[i+2] = multiply(a0,13) ^ multiply(a1,9) ^ multiply(a2,14) ^ multiply(a3,11)
        out[i+3] = multiply(a0,11) ^ multiply(a1,13) ^ multiply(a2,9) ^ multiply(a3,14)
    return out


def encrypt_block(block, round_keys):
    if len(block) != 16:
        raise ValueError("Blok AES harus tepat 16 byte.")

    state = list(block)
    state = add_round_key(state, round_keys[0])

    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return bytes(state)


def decrypt_block(block, round_keys):
    if len(block) != 16:
        raise ValueError("Blok AES harus tepat 16 byte.")

    state = list(block)
    state = add_round_key(state, round_keys[10])

    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)


def pad(data):
    amount = 16 - (len(data) % 16)
    return data + bytes([amount]) * amount


def unpad(data):
    if not data or len(data) % 16:
        raise ValueError("Data padding tidak valid.")

    amount = data[-1]
    if amount < 1 or amount > 16 or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("Data padding tidak valid.")

    return data[:-amount]


def encrypt(plaintext, key):
    round_keys = key_expansion(key)
    data = pad(plaintext)
    output = b""

    for i in range(0, len(data), 16):
        output += encrypt_block(data[i:i+16], round_keys)

    return output


def decrypt(ciphertext, key):
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("Ciphertext harus kelipatan 16 byte.")

    round_keys = key_expansion(key)
    output = b""

    for i in range(0, len(ciphertext), 16):
        output += decrypt_block(ciphertext[i:i+16], round_keys)

    return unpad(output)


if __name__ == "__main__":
    # AES-128 known-answer test, satu blok tanpa padding.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "69c4e0d86a7b0430d8cdb78070b4c55a"

    round_keys = key_expansion(key)
    ciphertext = encrypt_block(plaintext, round_keys)
    recovered = decrypt_block(ciphertext, round_keys)

    print("AES-128 manual self-test")
    print("Ciphertext :", ciphertext.hex())
    print("Expected   :", expected)
    print("Recovered  :", recovered.hex())
    print("STATUS     :", "PASS" if ciphertext.hex() == expected and recovered == plaintext else "FAIL")
