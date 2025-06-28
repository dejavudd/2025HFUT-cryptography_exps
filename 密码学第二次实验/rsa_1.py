import sys
import argparse
import random

from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15

# 添加命令行参数解析
parser = argparse.ArgumentParser(description="RSA 实验代码")
parser.add_argument('--method', type=int, choices=[1, 2], help="选择实现方式: 1 为自主实现, 2 为调用密码库")
args = parser.parse_args()

if args.method is None:
    while True:
        choice = input("请选择实现方式 (1 为自主实现, 2 为调用密码库): ")
        if choice == '1':
            args.method = 1
            break
        elif choice == '2':
            args.method = 2
            break
        else:
            print("无效的选择，请输入 1 或 2。")

# --- 方式一：自主实现基础版 RSA 算法 ---
if args.method == 1:
    print("\n--- 执行方式一：自主实现基础版 RSA 算法 ---")


    # 模重复指数运算 (a^b mod m)
    def power(a, b, m):
        res = 1
        a %= m
        while b > 0:
            if b % 2 == 1:
                res = (res * a) % m
            a = (a * a) % m
            b //= 2
        return res

    # 欧几里得算法求最大公约数
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    # 扩展欧几里得算法求模逆
    def extended_gcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return (gcd, y - (b // a) * x, x)

    def mod_inverse(a, m):
        gcd, x, y = extended_gcd(a, m)
        if gcd != 1:
            return None  # 模逆不存在
        else:
            return x % m

    # Miller-Rabin 素性测试
    def is_prime(n, k=5):
        # 特殊情况处理
        if n <= 1: return False
        if n <= 3: return True
        if n % 2 == 0: return False

        # 找到 r 和 s 使得 n-1 = 2^s * r, r 为奇数
        s = 0
        r = n - 1
        while r % 2 == 0:
            s += 1
            r //= 2

        # 见证者循环
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = power(a, r, n)
            if x != 1 and x != n - 1:
                for _ in range(s - 1):
                    x = power(x, 2, n)
                    if x == n - 1: break
                    if x == 1: return False
                else: return False
        return True

    # 生成指定比特长度的素数
    def generate_prime(bits):
        while True:
            # 生成指定比特长度的随机数
            p = random.getrandbits(bits)
            # 保证为奇数且在正确范围内
            p |= (1 << bits - 1) | 1
            if is_prime(p):
                return p

    # 生成 RSA 密钥对
    def generate_keys(bits=512):
        # 生成两个不同的大素数 p 和 q
        print("Generating prime p...")
        p = generate_prime(bits // 2)
        print("Generating prime q...")
        while True:
            q = generate_prime(bits // 2)
            if q != p:
                break

        # 计算 n = p * q
        n = p * q

        # 计算欧拉函数 phi(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)

        # 选择整数 e，满足 1 < e < phi 且 gcd(e, phi) = 1
        # 常用选择为 65537
        e = 65537
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)

        # 计算 d，使得 d 为 e 关于 phi 的模逆
        d = mod_inverse(e, phi)

        return ((e, n), (d, n)) # 公钥（e, n），私钥（d, n）

    def rsa_sign(message_hash, private_key):
        d, n = private_key
        # 签名 = hash^d mod n
        signature = power(message_hash, d, n)
        return signature


    def rsa_verify(message_hash, signature, public_key):
        e, n = public_key

        decrypted_hash = power(signature, e, n)

        return decrypted_hash == message_hash


    def string_to_int_hash(text):
        import hashlib

        hash_obj = hashlib.sha256(text.encode('utf-8'))
        # 将十六进制摘要转为整数
        return int(hash_obj.hexdigest(), 16)


    public_key, private_key = generate_keys(bits=512) 
    (e, n) = public_key
    (d, n_priv) = private_key # n_priv 应与 n 相同

    print("--- RSA Key Pair (Manual Implementation) ---")
    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n_priv})")
    print("-" * 25)

    name = "chenruoyu"  # 请替换为你的姓名
    student_id = "2023217422"  # 请替换为你的学号
    plaintext = name + student_id

    print(f"\nPlaintext: {plaintext}")


    message_hash_int = string_to_int_hash(plaintext)

    print(f"Hash (SHA-256 as Integer): {message_hash_int}")


    signature = rsa_sign(message_hash_int, private_key)
    print(f"Signature (Integer): {signature}")


    is_valid = rsa_verify(message_hash_int, signature, public_key)

    if is_valid:
        print("\nSignature verification successful!")
    else:
        print("\nSignature verification failed.")

# --- 方式二：调用现有密码库进行 RSA 实现 ---
elif args.method == 2:
    print("\n--- 执行方式二：调用现有密码库 ---")
    # 任务二：RSA 签名与验签
    # 1. 生成 RSA 密钥对（1024 位）
    key = RSA.generate(1024)  # Cryptodome 库的最小密钥长度为 1024 位
    print(f"Public Exponent (e): {key.e}")
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("--- RSA Key Pair（1024 bits）---")
    print("Private Key：")
    print(private_key.decode())
    print("\nPublic Key：")
    print(public_key.decode())
    print("-" * 25)


    name = "chenruoyu" 
    student_id = "2023217422" 
    plaintext = name + student_id

    print(f"\nPlaintext: {plaintext}")

    hash_obj = SHA256.new(plaintext.encode('utf-8'))

    print(f"Hash (SHA-256): {hash_obj.hexdigest()}")


    loaded_private_key = RSA.import_key(private_key)

    signer = pkcs1_15.new(loaded_private_key)
    signature = signer.sign(hash_obj)

    print(f"Signature: {signature.hex()}")


    loaded_public_key = RSA.import_key(public_key)

    verifier = pkcs1_15.new(loaded_public_key)

    try:
        verifier.verify(hash_obj, signature)
        print("\nSignature verification successful!")
    except (ValueError, TypeError):
        print("\nSignature verification failed.")
