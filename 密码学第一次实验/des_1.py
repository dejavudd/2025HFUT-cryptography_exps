import sys
import argparse
from Cryptodome.Cipher import DES

# 默认的8字节密钥和IV
DEFAULT_KEY = b'HFGYDX25'
DEFAULT_IV = b'12345678'

# =========================
# 简化版 DES 实现
# =========================

# 标准 DES 初始置换表 (IP) 及其逆置换表 (IP^-1)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# =========================
# 完整版 DES f 函数所需的表
# =========================

# 扩展置换表 (E)
E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
]

# S-盒
S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# P-盒
P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

# =========================
# 密钥调度相关表
# =========================

# PC-1: 置换选择1
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
]

# PC-2: 置换选择2
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

# 每轮的循环左移位数
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 整数 <-> 比特列表 转换
def int_to_bits(x: int, width: int) -> list:
    return [(x >> (width - 1 - i)) & 1 for i in range(width)]

def bits_to_int(bits: list) -> int:
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val

def permute(bits: list, table: list) -> list:
    return [bits[i - 1] for i in table]

def f_function(r_half: list, subkey: list) -> list:
    # 1. 扩展置换: 32位 -> 48位
    expanded_r = permute(r_half, E)
    # 2. 与子密钥异或
    xored = [r ^ k for r, k in zip(expanded_r, subkey)]
    # 3. S-盒代换: 48位 -> 32位
    s_box_out = []
    for i in range(8):
        chunk = xored[i*6 : i*6+6]
        # 行号由第1位和第6位决定
        row = (chunk[0] << 1) | chunk[5]
        # 列号由中间4位决定
        col = bits_to_int(chunk[1:5])
        # 从S-盒中查找值
        val = S_BOXES[i][row][col]
        # 将4位整数转换为4位比特列表
        s_box_out.extend(int_to_bits(val, 4))
    # 4. P-盒置换: 32位
    return permute(s_box_out, P)

def generate_round_keys(key_bytes: bytes) -> list:
    # 从8字节密钥生成16轮的48位子密钥
    key_int = int.from_bytes(key_bytes, 'big')
    key_bits = int_to_bits(key_int, 64)
    # PC-1置换: 64位 -> 56位
    permuted_key_56 = permute(key_bits, PC1)
    # 分为左右两半 C0, D0
    c, d = permuted_key_56[:28], permuted_key_56[28:]
    
    round_keys = []
    for i in range(16):
        # 循环左移
        shift = LEFT_SHIFTS[i]
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        # 合并并通过PC-2置换: 56位 -> 48位
        combined_cd = c + d
        subkey_48 = permute(combined_cd, PC2)
        round_keys.append(subkey_48)
        
    return round_keys

def manual_des_block(block_bytes: bytes, round_keys: list, decrypt=False) -> bytes:
    block_int = int.from_bytes(block_bytes, 'big')
    block_bits = int_to_bits(block_int, 64)
    permuted = permute(block_bits, IP)
    left, right = permuted[:32], permuted[32:]
    keys = round_keys[::-1] if decrypt else round_keys
    for k in keys:
        new_left = right
        fx = f_function(right, k)
        new_right = [l ^ f for l, f in zip(left, fx)]
        left, right = new_left, new_right
    combined = right + left
    final_bits = permute(combined, IP_INV)
    final_int = bits_to_int(final_bits)
    return final_int.to_bytes(8, 'big')

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

def manual_des_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(key) == 8, "密钥必须是 8 字节。"
    assert len(iv) == 8, "IV必须是 8 字节。"
    round_keys = generate_round_keys(key)
    
    padded_plaintext = pad_pkcs5(plaintext)
    blocks = [padded_plaintext[i:i+8] for i in range(0, len(padded_plaintext), 8)]
    
    ciphertext = b''
    prev_cipher_block = iv
    
    for block in blocks:
        # CBC mode: P_i XOR C_{i-1}
        block_to_encrypt = xor_bytes(block, prev_cipher_block)
        encrypted_block = manual_des_block(block_to_encrypt, round_keys, decrypt=False)
        ciphertext += encrypted_block
        prev_cipher_block = encrypted_block
        
    return ciphertext

def manual_des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(key) == 8, "密钥必须是 8 字节。"
    assert len(iv) == 8, "IV必须是 8 字节。"
    assert len(ciphertext) % 8 == 0, "密文长度必须是 8 字节的倍数。"
    round_keys = generate_round_keys(key)
    
    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    
    decrypted_padded = b''
    prev_cipher_block = iv
    
    for block in blocks:
        decrypted_block = manual_des_block(block, round_keys, decrypt=True)
        # CBC mode: D(C_i) XOR C_{i-1}
        plaintext_block = xor_bytes(decrypted_block, prev_cipher_block)
        decrypted_padded += plaintext_block
        prev_cipher_block = block
        
    return unpad_pkcs5(decrypted_padded)


def pad_pkcs5(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs5(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding: input data cannot be empty")
        
    pad_len = data[-1]
    
    if pad_len > 8 or pad_len == 0:
        raise ValueError("Invalid padding: padding length is out of range")
        
    if len(data) < pad_len:
        raise ValueError("Invalid padding: not enough data for padding specified")

    # 验证所有填充字节是否都与pad_len相等
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            raise ValueError("Invalid padding: incorrect padding bytes")
            
    return data[:-pad_len]

def library_des_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad_pkcs5(plaintext)
    return cipher.encrypt(padded)

def library_des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad_pkcs5(decrypted)

# =========================
# 命令行接口与演示
# =========================
def main():
    parser = argparse.ArgumentParser(description="DES (CBC Mode)")
    parser.add_argument('--mode', choices=['enc', 'dec'], required=False, default='enc', help='加密(enc)或解密(dec)')
    parser.add_argument('--type', choices=['manual', 'lib'], required=False, default='manual', help='算法类型: manual(自主实现)或lib(库版)')
    parser.add_argument('--key', type=str, required=False, help='8字节密钥（可选，默认使用内置密钥）')
    parser.add_argument('--iv', type=str, required=False, help='8字节IV (可选，默认使用内置IV)')
    parser.add_argument('--data', type=str, required=False, default='ABCDEFGH', help='明文或密文（base16/utf8）')
    parser.add_argument('--hex', action='store_true', help='数据是否为16进制(hex)输入/输出')
    args = parser.parse_args()

    # 使用默认密钥或用户提供的密钥
    key = args.key.encode('utf-8') if args.key else DEFAULT_KEY
    if len(key) != 8:
        print('密钥必须为8字节！')
        sys.exit(1)
    
    iv = args.iv.encode('utf-8') if args.iv else DEFAULT_IV
    if len(iv) != 8:
        print('IV必须为8字节！')
        sys.exit(1)

    if args.mode == 'enc':
        if args.hex:
            data = bytes.fromhex(args.data)
        else:
            data = args.data.encode('utf-8')
        if args.type == 'manual':
            ct = manual_des_encrypt(data, key, iv)
        else:
            ct = library_des_encrypt(data, key, iv)
        # 解密时总是需要hex,所以加密也统一输出hex
        print(f'Ciphertext: {ct.hex()}')
    else:
        try:
            data = bytes.fromhex(args.data)
        except ValueError:
            print("解密数据必须是有效的十六进制字符串。")
            sys.exit(1)

        if args.type == 'manual':
            pt = manual_des_decrypt(data, key, iv)
        else:
            pt = library_des_decrypt(data, key, iv)
        # 相应地，解密输出也根据hex flag来
        print(f'Decrypted : {pt.hex() if args.hex else pt.decode("utf-8", errors="replace")}')

# =========================
# 简单单元测试
# =========================
def test():
    key = b'8bytekey'
    iv = b'my8byteiv'
    data = b'This is a test message that is longer than one block.'
    
    print("=" * 20)
    print("      DES 实现对比测试")
    print("=" * 20)
    print(f"明文: {data.decode()}")
    print(f"密钥: {key.decode()}")
    print(f"IV  : {iv.decode()}")
    print("-" * 20)
    
    # 1. 手动实现
    print("[测试] 自主实现 DES (CBC Mode):")
    manual_ct = manual_des_encrypt(data, key, iv)
    manual_pt = manual_des_decrypt(manual_ct, key, iv)
    print(f'密文 (hex): {manual_ct.hex()}')
    print(f'解密结果: {manual_pt.decode()}')
    assert data == manual_pt, "自主实现DES解密失败！"
    print("自主实现加解密... OK")
    print("-" * 20)

    # 2. 库版实现
    print("[测试] 库版 DES (CBC Mode):")
    lib_ct = library_des_encrypt(data, key, iv)
    lib_pt = library_des_decrypt(lib_ct, key, iv)
    print(f'密文 (hex): {lib_ct.hex()}')
    print(f'解密结果: {lib_pt.decode()}')
    assert data == lib_pt, "库版DES解密失败！"
    print("库版加解密... OK")
    print("-" * 20)
    
    # 3. 对比验证
    print("[验证] 对比两种实现的密文...")
    assert manual_ct == lib_ct, "自主实现与库版DES加密结果不一致！"
    print("两种实现结果完全一致... PASS!")
    print("=" * 20)

if __name__ == "__main__":
    # 添加一个test命令的入口
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'test':
        test()
    elif len(sys.argv) == 1:
        # 无参数时进入交互模式
        print("请选择 DES 实现方式 (输入 manual 或 lib):")
        type_choice = input().lower()
        while type_choice not in ['manual', 'lib']:
            print("无效输入。请选择 manual 或 lib:")
            type_choice = input().lower()

        print("请选择操作模式 (输入 enc 进行加密，dec 进行解密):")
        mode_choice = input().lower()
        while mode_choice not in ['enc', 'dec']:
            print("无效输入。请选择 enc 或 dec:")
            mode_choice = input().lower()

        # --- Key Input with Validation ---
        while True:
            key_input_str = input(f"请输入8字节密钥 (留空使用默认: {DEFAULT_KEY.decode('utf-8')}): ")
            if not key_input_str:
                key = DEFAULT_KEY
                print(f"使用默认密钥: {key.decode('utf-8')}")
                break
            
            key = key_input_str.encode('utf-8')
            if len(key) == 8:
                break
            else:
                print(f"  [错误] 密钥必须是8字节。您输入的长度为 {len(key)} 字节。请重新输入。")
        
        # --- IV Input with Validation ---
        while True:
            iv_input_str = input(f"请输入8字节IV (留空使用默认: {DEFAULT_IV.decode('utf-8')}): ")
            if not iv_input_str:
                iv = DEFAULT_IV
                print(f"使用默认IV: {iv.decode('utf-8')}")
                break
            
            iv = iv_input_str.encode('utf-8')
            if len(iv) == 8:
                break
            else:
                print(f"  [错误] IV必须是8字节。您输入的长度为 {len(iv)} 字节。请重新输入。")

        data_input_str = input(f"请输入要{'加密' if mode_choice == 'enc' else '解密'}的数据 ({'明文' if mode_choice == 'enc' else '密文的十六进制表示'}): ")

        if mode_choice == 'enc':
            data = data_input_str.encode('utf-8')
            if type_choice == 'manual':
                result = manual_des_encrypt(data, key, iv)
            else:
                result = library_des_encrypt(data, key, iv)
            print(f'密文 (十六进制): {result.hex()}')
        else:
            try:
                data = bytes.fromhex(data_input_str)
                if type_choice == 'manual':
                    result = manual_des_decrypt(data, key, iv)
                else:
                    result = library_des_decrypt(data, key, iv)
                print(f'解密结果: {result.decode("utf-8", errors="replace")}')
            except ValueError as e:
                # 捕获我们增强后的反填充错误，以及可能的hex格式错误
                if 'padding' in str(e):
                    print("解密失败: 密钥或IV错误，或密文已损坏。 (Padding Error)")
                else:
                    print(f"输入错误: {e}")
                sys.exit(1)
    else:
        main()
