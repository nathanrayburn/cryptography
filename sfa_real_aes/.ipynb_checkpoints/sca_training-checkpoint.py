import numpy as np

rcon = np.array([
[0x01, 0x00, 0x00, 0x00], 
[0x02, 0x00, 0x00, 0x00], 
[0x04, 0x00, 0x00, 0x00], 
[0x08, 0x00, 0x00, 0x00], 
[0x10, 0x00, 0x00, 0x00], 
[0x20, 0x00, 0x00, 0x00], 
[0x40, 0x00, 0x00, 0x00], 
[0x80, 0x00, 0x00, 0x00], 
[0x1b, 0x00, 0x00, 0x00], 
[0x36, 0x00, 0x00, 0x00],
[0x6c, 0x00, 0x00, 0x00],
[0xd8, 0x00, 0x00, 0x00],
[0xab, 0x00, 0x00, 0x00],
[0xed, 0x00, 0x00, 0x00],
[0x9a, 0x00, 0x00, 0x00]], dtype=np.uint8, )


Sbox_tab = np.array([
0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16], dtype=np.uint8)


invSbox = np.array([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d], dtype=np.uint8)


# This function takes a 1D or 2D numpy array as AES round keys and returns
# a key schedule as a 3D array.
# Each column of a master_keys contains key bytes. One row is one master key.
def key_expansion_from_round_key(round_key, round):

    assert round_key.shape[-1] in [16, 24, 32], 'Only the following key sizes are supported by AES standard: 16, 24, 32. The given number of key bytes is {:d}.'.format(round_key.shape[-1])
    assert round_key.ndim <= 2, 'Currently only one or two dimensional master key arrays can be processed. Each row is a master key. Current number of dimensions is {:d}'.format(round_key.ndim)

    # Nk - number of AES words. This parameter depends on the key size. Available values 4, 6, 8
    # Nr - number of rounds. This parameter depends on the key size. Available values 10, 12, 14
    # The Key Expansion generates a total of 4*(Nr+1) words
    Nb = 4
    Nk = round_key.shape[-1] // Nb
    Nr = Nk + 6
    
    assert round <= Nr and round >= 0, 'The requested round {:d} can not be used for this AES. The range for rounds is [0,{:d}]'.format(round, Nr)

    if len(round_key.shape) == 1:
        num_rows = 1
    else:
        num_rows = round_key.shape[0]

    # key_schedule = np.zeros((num_rows, 16*(Nr+1)), dtype=np.uint8)

    key_schedule = np.zeros((num_rows, 16*(Nr+1)), dtype=np.uint8)

    #Perform the direct key expansion
    for i in range(Nb*round, Nb*(Nr+1)):
        #Copy master key bytes to the key schedule (first Nk words of 4 bytes)
        if i < Nb*round+Nk:
            key_schedule[..., Nb*i:Nb*(i+1)] = round_key[..., Nb*(i - Nb*round):Nb*(i - Nb*round +1)]
            continue

        temp = key_schedule[..., Nb*(i-1):Nb*i]

        if (i % Nk == 0):
            # Key word transformation            
            temp = np.bitwise_xor(Sbox_tab[temp[..., [1,2,3,0]]], rcon[i // Nk - 1,:]) #temp[..., [1,2,3,0] is a rotation operation of temp[..., [0,1,2,3]
        elif (Nk > 6) and (i % Nk == Nb):
            # This is tailored AES-256 operation
            temp = Sbox_tab[temp]

        key_schedule[..., Nb*i:Nb*(i+1)] = np.bitwise_xor(key_schedule[..., Nb*(i-Nk):Nb*(i+1-Nk)], temp)

    #Perform the reverse key expansion
    for i in range(Nb*round-1, -1, -1):
        temp = key_schedule[..., Nb*(i+Nk-1):Nb*(i+Nk)]

        if (i % Nk == 0):    
            # Key word transformation         
            temp = np.bitwise_xor(Sbox_tab[temp[..., [1,2,3,0]]], rcon[i // Nk,:]) #temp[..., [1,2,3,0] is a rotation operation of temp[..., [0,1,2,3]
        elif (Nk > 6) and (i % Nk == Nb):
            # This is tailored AES-256 operation
            temp = Sbox_tab[temp]

        key_schedule[..., Nb*(i):Nb*(i+1)] = np.bitwise_xor(key_schedule[..., Nb*(i+Nk):Nb*(i+Nk+1)], temp)

    return key_schedule.reshape(num_rows, Nr+1, 16)


def key_expansion(master_keys):
    return key_expansion_from_round_key(master_keys, 0)


def key_expansion_128(master_keys):
    assert master_keys.shape[-1] == 16, 'AES-128 requres 16 input bytes.'

    return key_expansion(master_keys)


def key_expansion_192(master_keys):
    assert master_keys.shape[-1] == 24, 'AES-192 requres 24 input bytes.'

    return key_expansion(master_keys)


def key_expansion_256(master_keys):
    assert master_keys.shape[-1] == 32, 'AES-256 requres 32 input bytes.'

    return key_expansion(master_keys)


def inverse_key_expansion(last_round_keys):
    assert last_round_keys.shape[-1] in [16, 24, 32]

    last_round = last_round_keys.shape[-1] // 4 + 6
    return key_expansion_from_round_key(last_round_keys, last_round)

def get_master_key(last_round_key):
    m_k = inverse_key_expansion(last_round_key)[0,0]
    return m_k


HW_uint8 = np.array([bin(x).count('1') for x in range(256)], dtype=np.uint8)

def inv_shift_rows(state):

    suffle_ind = np.array([0, 13, 10, 7,  4, 1, 14, 11,  8, 5, 2, 15,  12, 9, 6, 3], dtype=np.uint8)
    
    if (len(state.shape) == 2):
        return state[:,suffle_ind]
    
    if (len(state.shape) == 1):
        return state[suffle_ind]
    
    return NULL


def shift_rows(state):

    suffle_ind = np.array([0, 5, 10, 15,  4, 9, 14, 3,  8, 13, 2, 7,  12, 1, 6, 11], dtype=np.uint8)
    
    if (len(state.shape) == 2):
        return state[:,suffle_ind]
    
    if (len(state.shape) == 1):
        return state[suffle_ind]
    
    return NULL
