import random
#Tinh n qua lau, n > p ==> can kiem tra diem co thuoc duong thang khong, hien cac diem cho nguoi dung chonj, hien so diem cua duong cong
def mod_sqrt(a, p):
    """ Tìm căn bậc 2 của a mod p sử dụng phương pháp Tonelli-Shanks (nếu tồn tại) """
    if a == 0:
        return 0
    if p == 2:
        return a % p
    # Điều kiện bậc 2 tồn tại với a mod p
    if pow(a, (p - 1) // 2, p) != 1:
        return None  # Không tồn tại căn bậc 2


    # Phương pháp Tonelli-Shanks
    s, q = 0, p - 1
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 2
    while pow(z, (p - 1) // 2, p) == 1:
        z += 1


    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 0 and t != 1:
        t2i = t
        i = 0
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                break
        b = pow(c, 2**(m - i - 1), p)
        m = i
        c = b**2 % p
        t = (t * b**2) % p
        r = (r * b) % p
    return r if t == 1 else None
def message_to_point(p, a, b, message):
    # Chuyển thông điệp thành chuỗi các mã ASCII
    message_bytes = message.encode('utf-8')
    message_int = int.from_bytes(message_bytes, 'big')  # Chuyển thành số nguyên
    # Tìm giá trị x sao cho x^3 + ax + b = y^2 mod p có nghiệm
    x = message_int % p  # Sử dụng số nguyên của thông điệp làm giá trị x
    while True:
        # Tính giá trị của y^2 = x^3 + ax + b mod p
        y_square = (x**3 + a * x + b) % p


        # Kiểm tra nếu y_square có căn bậc 2 modulo p
        y = mod_sqrt(y_square, p)
        if y is not None:
            # Trả về điểm (x, y) trên đường cong elliptic
            return x, y
        # Nếu không có nghiệm, thử với x khác
        x = (x + 1) % p
       


def check_condition(p, a, b):
    a = int(a)  # Convert 'a' to integer
    b = int(b)  # Convert 'b' to integer
    return (4 * a**3 + 27 * b**2) % p != 0


   
def add_points( p, a, b, x1, y1, x2, y2):
        if (x1, y1) == (0, 0):
            return (x2, y2)
        if (x2, y2) == (0, 0):
            return (x1, y1)
        if x1 == x2 and y1 == -y2 % p:
            return (0, 0)
        if x1 == x2 and y1 == y2:
            m = (3 * x1**2 + a) * pow(2 * y1, -1, p) % p
        else:
            m = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
        x3 = (m**2 - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)
   
def point_subtract(P1, P2):
    return add_points(P1[0], P1[1], -P2[0], -P2[1])


def multiply_elliptic(p, a, b, k, x, y):
    # Đầu tiên, điểm G được biểu diễn bằng (x, y).
    result_x, result_y = 0, 0  # Điểm vô cùng (0, 0)
    base_x, base_y = x, y


    # Lặp qua từng bit trong k từ trái qua phải (nhị phân).
    while k > 0:
        if k % 2 == 1:  # Nếu bit hiện tại là 1, ta cộng điểm
            result_x, result_y = add_points(p, a, b, result_x, result_y, base_x, base_y)
       
        # Tạo điểm cơ sở gấp đôi nó lại.
        base_x, base_y = add_points(p, a, b, base_x, base_y, base_x, base_y)
       
        # Tiến đến bit tiếp theo.
        k //= 2


    return result_x, result_y


def scalar_multiply(P, k, p, a, b):
    result = (0, 0)  # Điểm vô cùng
    addend = P
    while k > 0:
        if k % 2 == 1:
            result = add_points(result, a, b, addend[0], addend[1], p)
        addend = add_points(addend, a, b, addend[0], addend[1], p)
        k //= 2
    return result






def find_elip_points(p, a, b, num_points=1000):
    points = []
    for x in range(1, num_points + 1):  # Duyệt qua số lượng điểm nhất định để tránh chậm
        rhs = (x**3 + a*x + b) % p
        y = mod_sqrt(rhs, p)
        if y is not None:
            points.append((x, y))  # Điểm (x, y)
            if y != 0:
                points.append((x, p - y))  # Điểm đối xứng (x, -y)
    return points
def check_point(p, a, b, x, y):
    return (y**2) % p == (x**3 + a*x + b) % p
def random_a_point(p, a, b):
    points = find_elip_points(p, a, b, num_points=1000)
    return points[0]
def caculate_order(p, a, b, x, y):
    n = 1
    current_x, current_y = x, y
    while (current_x, current_y) != (0, 0):  # Khi điểm là điểm vô cùng
        n += 1
        current_x, current_y = multiply_elliptic(p, a, b, 1, current_x, current_y)
        if n > p:  # Thứ tự của điểm không thể vượt quá modulo p
            raise ValueError("Không tìm thấy thứ tự hợp lệ trong phạm vi modulo p.")
    return n
def generate_elliptic_keys(p, a, b, G, s):
    n = caculate_order(p, a, b, G[0], G[1])
    P = multiply_elliptic(p, a, b, s, G[0], G[1])
    return(n, G, P), s, (P[0], P[1])


def encrypt_elliptic(p, a, b, message, public_key, k):
    n, G, P = public_key  # Khóa công khai gồm n, G, P


    # Chuyển thông điệp thành điểm trên đường cong
    M = message_to_point(p, a, b, message)


    # Tạo một số ngẫu nhiên k
    C1 = scalar_multiply(G, k, p, a, b)  # C1 = k * G (Điểm ngẫu nhiên)
    C2 = add_points(M, scalar_multiply(P, k, p, a, b))  # C2 = M + k * P (Điểm mã hóa)


    return C1, C2
def decrypt_elliptic(p, a, b, C1, C2, private_key):
    s = private_key  # Khóa riêng
    # Tính toán s * C1
    C1_s = scalar_multiply(C1, s, p, a, b)  # C1_s = s * C1
    # Giải mã C2 bằng cách trừ C1_s từ C2: M = C2 - C1_s
    M = point_subtract(C2, C1_s)  # M = C2 - s * C1
    # Chuyển điểm M thành thông điệp
    return M


def main():
    # 1. Khởi tạo các tham số của đường cong elliptic
    p = 11  # Số nguyên tố (module)
    a = 1   # Tham số a
    b = 6   # Tham số b


    # Kiểm tra tính hợp lệ của tham số đường cong
    if not check_condition(p, a, b):
        print("Tham số không hợp lệ, đường cong không khả thi.")
        return


    # 2. Sinh điểm cơ sở G
    G = [2, 7]
    n = caculate_order(p, a, b, G[0], G[1])
    print(f"Điểm cơ sở G: {G}")
    print(f"Độ lớn nhóm: {n}")


    # 3. Sinh khóa riêng và khóa công khai
    # private_key = random.randint(1, 10)  # Khóa riêng s (bí mật)
    # public_key = generate_elliptic_keys(p, a, b, G, private_key)
    # print(f"Khóa riêng: {private_key}")
    # print(f"Khóa công khai: {public_key}")


    # # 4. Mã hóa thông điệp
    # message = "HELLO"
    # k = random.randint(1, 10)  # Số ngẫu nhiên cho mỗi lần mã hóa
    # print(f"Thông điệp ban đầu: {message}")


    # encrypted = encrypt_elliptic(p, a, b, message, public_key, k)
    # print(f"Thông điệp đã mã hóa: {encrypted}")


    # # 5. Giải mã thông điệp
    # decrypted = decrypt_elliptic(p, a, b, encrypted[0], encrypted[1], private_key)
    # print(f"Điểm thông điệp sau khi giải mã: {decrypted}")


    # # 6. Kiểm tra tính đúng đắn
    # if decrypted:
    #     try:
    #         # Chuyển điểm M về thông điệp dạng string
    #         x = decrypted[0]
    #         decoded_message = x.to_bytes((x.bit_length() + 7) // 8, 'big').decode('utf-8')
    #         print(f"Thông điệp sau khi giải mã: {decoded_message}")
    #     except Exception as e:
    #         print("Không thể chuyển đổi điểm giải mã thành thông điệp:", e)
    # else:
    #     print("Giải mã thất bại.")
if __name__ == "__main__":
    main()
