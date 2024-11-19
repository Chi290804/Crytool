import random

def mod_exp(base, exp, mod):
    if not (isinstance(base, int) and isinstance(exp, int) and isinstance(mod, int)):
        raise TypeError("Base, exponent, and modulus must be integers")
    
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
def caculate_n(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    return n, phi_n
def generate_rsa_keys(n, phi_n, e):

    # Chọn e ngẫu nhiên sao cho gcd(e, phi_n) = 1
    # e = random.randrange(2, phi_n)
    # while gcd(e, phi_n) != 1:
    #     e = random.randrange(2, phi_n)
    # Tính d là nghịch đảo của e modulo phi_n
    d = pow(e, -1, phi_n)
    
    # Private key: (n, d), Public key: (n, e)
    return (n, d), (n, e)

def encrypt_message(message, public_key):
    n, e = public_key
    
    # Nếu message là chuỗi, mã hóa nó thành số nguyên
    if isinstance(message, str):
        message_int = hashing(message)  # Sử dụng hàm hashing để chuyển đổi
    elif isinstance(message, int):
        message_int = message
    else:
        raise ValueError("Message must be a string or integer")

    # Mã hóa message
    encrypted_message = mod_exp(message_int, e, n)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    n, d = private_key
    decrypted_message_int = mod_exp(int(encrypted_message), d, n)
    # decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode()
    # decrypted_message = dehashing(decrypted_message_int)
    return decrypted_message_int
def hashing(txt):
    
    # txt = txt.upper()
    
    ans = 0
    
    for c in txt:
        ans = ans * 26 + (ord(c) - ord('A'))
    
    return ans

def dehashing(num):
    result = []
    
    while num > 0:
        remainder = num % 26
        char = chr(ord('A') + remainder)  # Chuyển đổi số thành ký tự
        result.append(char)
        num = num // 26
    
    # Đảo ngược chuỗi vì ta lấy phần dư từ cuối đến đầu
    result.reverse()
    return ''.join(result)