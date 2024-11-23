# %%
import math
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
# %%
class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        
        if not self.check_condition(a, b, p):
            raise ValueError("The curve is not valid")
        
    def check_condition(self, a, b, p):
        return (4*a**3 + 27*b**2) % p != 0

    def is_point_on_curve(self, point):
        x, y = point
        return (y**2) % self.p == (x**3 + self.a*x + self.b) % self.p

    def add_points(self, p1, p2):
        x1, y1 = p1
        x2, y2 = p2
        if p1 == (0, 0):
            return p2
        if p2 == (0, 0):
            return p1
        if x1 == x2 and y1 == -y2 % self.p:
            return (0, 0)
        if x1 == x2 and y1 == y2:
            m = (3*x1**2 + self.a) * pow(2*y1, -1, self.p) % self.p
        else:
            m = (y2 - y1) * pow((x2 - x1) % self.p, -1, self.p) % self.p
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m*(x1 - x3) - y1) % self.p
        return (x3, y3)

    def multiply_point(self, point, n):
        if n == 0:
            return (0, 0)
        if n == 1:
            return point
        if n % 2 == 0:
            return self.multiply_point(self.add_points(point, point), n // 2)
        return self.add_points(point, self.multiply_point(self.add_points(point, point), (n - 1) // 2))
    
    #calculate p1 - p2
    def subtract_points(self, p1, p2):
        x2, y2 = p2
        return self.add_points(p1, (x2, -y2 % self.p))

    def get_points(self):
        points = []
        for x in range(self.p):
            y = self.get_y(x)
            
            if (y == None):
                continue
            
            if (y[0] != 0):
                points.append((x, y[0]))
                points.append((x, y[1]))
                
            if len(points) > 500:
                break
            
        return points
    
    def check_quadratic_residue(self, x):
        return pow(x, (self.p - 1) // 2, self.p) == 1
    
    def get_y(self, x):
        
        a = (x**3 + self.a*x + self.b) % self.p
        
        if not self.check_quadratic_residue(a):
            return None
        
        if (self.p % 4 == 3):
            m = (self.p - 3) // 4
            return pow(a, (m + 1), self.p), -pow(a, (m + 1), self.p) % self.p
        else:
            raise ValueError("Not implemented yet, p % 4 != 3")
    
    def get_order(self, point):
        order = 1
        while True:
            if self.multiply_point(point, order) == (0, 0):
                return order
            order += 1


# %%
class EllipticCurveCryptography():
    def __init__(self, curve, G, n):
        # curve is an instance of EllipticCurve
        self.curve = curve
        # G is a point on the curve
        self.G = G
        # n is the order of the curve
        self.n = curve.get_order(G)
        
        self.s = 1811
        self.B = self.curve.multiply_point(self.G, self.s)
        
        
    def get_B(self):
        return self.B
    def get_public_key(self):
        return (self.curve.p, self.curve.a, self.curve.b, self.n, self.G, self.B)
    
    def get_private_key(self, s):
        self.s = s
        return self.s

    def encrypt(self, M, k):
        M1 = self.curve.multiply_point(self.G, k)
        M2 = self.curve.add_points(M, self.curve.multiply_point(self.B, k))
        return (M1, M2)

    def decrypt(self, C1, C2, s):
        return self.curve.subtract_points(C2, self.curve.multiply_point(C1, s))

# %%
import random

class participant():
    #M is the message to be signed, which is a point on the curve
    def __init__(self, curve, G, n, M, signature):
        self.ECC = EllipticCurveCryptography(curve, G, n)
        
        self.M = M
        self.signature = signature
    
    def encrypt_message(self, other):
        return other.ECC.encrypt(self.M)
    
    def decrypt_message(self, other, C1, C2):
        return other.ECC.decrypt(C1, C2)
    
    def encrypt_signature(self, s):
        n, G, B = self.ECC.get_public_key()[1:]
        s = self.ECC.get_private_key(s)
        
        while(True):
            k = random.randint(1, n - 1)
            
            M1 = self.ECC.curve.multiply_point(G, k)
            
            r = M1[0] % n
            
            if r == 0:
                continue
            
            h = hashing(self.signature)
            
            u = (h + pow(s, r, n)) * pow(k, -1, n) % n
            
            if u == 0:
                continue
            
            return (r, u)
    
    def decrypt_signature(self, cipher, s):
        r, u = cipher
        n, G, B = self.ECC.get_public_key()[1:]
        s = self.ECC.get_private_key(s)
        
        w = pow(u, -1, n)
        h = hashing(self.signature)
        u1 = h * w % n
        u2 = r * w % n
        
        P = self.ECC.curve.add_points(self.ECC.curve.multiply_point(G, u1), self.ECC.curve.multiply_point(B, u2))
        
        return True


##
# ĐỂ TẠO API
##

def check_curve_conditions(a, b, p):
    try:
        curve = EllipticCurve(a, b, p)
        return True
    except ValueError:
        return False

def get_points_on_curve(a, b, p):
    curve = EllipticCurve(a, b, p)
    return curve.get_points()

def is_point_valid(a, b, p, point):
    curve = EllipticCurve(a, b, p)
    return curve.is_point_on_curve(point)

def get_random_point_on_curve(a, b, p):
    curve = EllipticCurve(a, b, p)
    points = curve.get_points()
    return random.choice(points) if points else None

def calculate_order_of_point(a, b, p, G):
    curve = EllipticCurve(a, b, p)
    if curve.is_point_on_curve(G):
        return curve.get_order(G)
    return None

def generate_keys(a, b, p, G, n, s):
    curve = EllipticCurve(a, b, p)
    ecc = EllipticCurveCryptography(curve, G, n)
    private_key = ecc.get_private_key(s)
    public_key = ecc.get_B()
    # public_key = ecc.get_public_key()
    return private_key, public_key

def map_message_to_curve(a, b, p, message):
    curve = EllipticCurve(a, b, p)
    x = hashing(message)
    while True:
        try:
            y = curve.get_y(x)
            if y:
                return (x, y[0])  # Lấy một nghiệm y
        except ValueError:
            pass
        x += 1

def encrypt_message(a, b, p, G, n, message, k):
    curve = EllipticCurve(a, b, p)
    ecc = EllipticCurveCryptography(curve, G, n)
    M = map_message_to_curve(a, b, p, message)
    return ecc.encrypt(M, k)

def decrypt_message(a, b, p, G, n, encrypted_message, s):
    curve = EllipticCurve(a, b, p)
    ecc = EllipticCurveCryptography(curve, G, n)
    C1, C2 = encrypted_message
    decrypted_point = ecc.decrypt(C1, C2, s)
    return decrypted_point

def sign_message(a, b, p, G, n, h, k, s):
    curve = EllipticCurve(a, b, p)
    ecc = EllipticCurveCryptography(curve, G, n)
    # Map thông điệp thành điểm trên đường cong (nếu cần)  
    # Tính điểm R = k * G
    R = curve.multiply_point(G, k)
    r = R[0] % n  # r là hoành độ của R (mod n)
    if r == 0:
        raise ValueError("R[0] mod n == 0, chọn k khác.")

    # Tính giá trị u (signature)
    k_inv = pow(k, -1, n)  # k^-1 mod n
    u = (h + s * r) * k_inv % n  # u = (h + s * r) * k^-1 mod n
    if u == 0:
        raise ValueError("u == 0, chọn k khác.")
    
    return (r, u)

def verify_signature(a, b, p, G, n, message, h, signature, B):
    """
    Xác minh chữ ký số.
    Input:
        a, b, p: Các tham số đường cong elliptic.
        G: Điểm cơ sở.
        n: Bậc của điểm cơ sở.
        message: Thông điệp cần xác minh.
        signature: Chữ ký (r, u).
        B: Khóa công khai (public key).
    Output:
        True nếu chữ ký hợp lệ, False nếu không.
    """
    r, u = signature
    curve = EllipticCurve(a, b, p)
    
    if not (1 <= r < n and 1 <= u < n):
        return False

    w = pow(u, -1, n)  # w = u^-1 mod n

    # Tính u₁ và u₂
    u1 = h * w % n
    u2 = r * w % n

    # Tính điểm P = u₁ * G + u₂ * B
    P = curve.add_points(
        curve.multiply_point(G, u1),
        curve.multiply_point(B, u2)
    )
    
    # Kiểm tra chữ ký hợp lệ nếu r ≡ P.x mod n
    return (P[0] % n == r), w, u1, u2, P

# Thông số đường cong
a, b, p = 1, 6, 11
G = (3, 5)
message = "HELLO"

# 1. Kiểm tra điều kiện
print("Điều kiện hợp lệ:", check_curve_conditions(a, b, p))

# 2. Lấy điểm trên đường cong
print("Các điểm trên đường cong:", get_points_on_curve(a, b, p))

# 3. Kiểm tra điểm G
print("G có thuộc đường cong không:", is_point_valid(a, b, p, G))

# 4. Lấy điểm ngẫu nhiên
random_point = get_random_point_on_curve(a, b, p)
print("Điểm ngẫu nhiên trên đường cong:", random_point)

# 5. Tính bậc của điểm G
n = calculate_order_of_point(a, b, p, G)
print("Bậc của G:", n)

# 6. Tạo khóa
private_key, public_key = generate_keys(a, b, p, G, n, s = 1811)
print("Khóa bí mật:", private_key)
print("Khóa công khai:", public_key)

# 7. Mã hóa và giải mã tin nhắn
poi = map_message_to_curve(a, b, p, message)
print("M:", poi)

encrypted_message = encrypt_message(a, b, p, G, n, message, k = 2)
print("Tin nhắn đã mã hóa:", encrypted_message)

decrypted_point = decrypt_message(a, b, p, G, n, encrypted_message, s = 1811)
print("Tin nhắn đã giải mã:", decrypted_point)
