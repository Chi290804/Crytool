#Nhan p, hien alpha, chon a, tinhs beta, chon m, chon k

import random
def mod_exp(base, exp, mod):
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

def is_prime(n):
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n < 2:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(100):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def find_prime_factors(n):
    factors = set()
    while n % 2 == 0:
        factors.add(2)
        n //= 2
    for i in range(3, int(n**0.5) + 1, 2):
        while n % i == 0:
            factors.add(i)
            n //= i
    if n > 2:
        factors.add(n)
    return factors

def find_primitive_root(p):
    if p == 2:
        return 1  

    phi = p - 1
    prime_factors = find_prime_factors(phi)
    
    for g in range(2, min(p, 1000)):  
        is_primitive = True
        for q in prime_factors:
            if pow(g, phi // q, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g  
    
    return None

def generate_elgamal_keys(p, a):
    alpha = 2
    k = random.randint(2, p - 2)
    beta = mod_exp(alpha, a, p)
    return (p, alpha, beta), (p, alpha, a)

def encrypt_elgamal(message, public_key, k):
    p, alpha, beta = public_key
    #Khóa phiên k được random mỗi lần chạy vậy nên bản mã sẽ khác nhau
    #Trong ví dụ trong file word đính kèm, khóa phiên k có giá trị
    
    #k = 231829683515004285894248732404818838505780640291715123088889449666416885328634740604061367009552293107004845199650478342025302430924465040754743126387968600172838303296241667234672358030056988574445077392877459316860987264706489823044426733783629485383174221974246710107609888722370369714382438004845162844505
    #Kết thúc hàm tính k ngẫu nhiên
    print(f"k: {k}")
    s = mod_exp(beta, k, p)
    c1 = mod_exp(alpha, k, p)
    message_int = hashing(message)
    c2 = (message_int * s) % p
    
    return c1, c2, k

def decrypt_elgamal(ciphertext, private_key):
    c1, c2 = ciphertext
    p, alpha, a = private_key
    x = p - a
    s = mod_exp(c1, x, p)
    
    s_inverse = pow(s, -1, p)
    
    message_int = (c2 * s_inverse) % p
    print(f"Bản rõ: {message_int}")

    message_bytes = dehashing(ciphertext)
    return message_bytes.decode()


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
