import hashlib
import random
from flask import Flask, request, jsonify, render_template
import rsa_backend as rsa_backend
import elgammal_backend as elgammal_backend
import elliptic_backend as elliptic_backend
 
app = Flask(__name__)


@app.route('/')
def rsa():
    return render_template('rsa_screen.html')

@app.route('/rsa-signature')
def rsaSign():
    return render_template('rsa_signature.html')

@app.route('/elgammal')
def elgammal():
    return render_template('elgammal.html')

@app.route('/elgammal-signature')
def elgammalSign():
    return render_template('elgamal_signature.html')

@app.route('/elliptic')
def elliptic():
    return render_template('elliptic.html')

@app.route('/elliptic-signature')
def ellipticSign():
    return render_template('elliptic_signature.html')

@app.route('/euclid')
def euclid():
    return render_template('euclid.html')

@app.route('/primality')
def primality():
    return render_template('primality.html')


@app.route('/check_coprime', methods=['POST'])
def check_coprime():
    data = request.json
    e = data.get('e')
    phi_n = data.get('phi_n')
    isCoprime = rsa_backend.gcd(e, phi_n) == 1
    return jsonify({
        "isCoprime": isCoprime
    })    

@app.route('/caculate', methods=['POST'])
def caculate():
    # Get the public key from the request
    data = request.json
    p = data.get('p')
    q = data.get('q')
    p = int(p)
    q = int(q)
    private_key, public_key = rsa_backend.caculate_n(p, q)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    return jsonify({
        'n': n,
        'phi_n': phi_n,
    })

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    e = int(data.get('e'))
    n = int(data['n'])
    phi_n = int(data['phi_n'])
    private_key, public_key = rsa_backend.generate_rsa_keys(n, phi_n, e)

    return jsonify({
        'public_key': public_key,
        'private_key': private_key
    })

@app.route('/encrypt-rsa', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')  # Lấy message từ JSON

    # Đảm bảo message không null
    if message is None:
        return jsonify({"error": "Message is required"}), 400
    message_int = rsa_backend.hashing(message)
    public_key = tuple(data.get('public_key'))
    
    # Gọi hàm mã hóa
    try:
        encrypted_message = rsa_backend.encrypt_message(message_int, public_key)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({'encrypted_message': encrypted_message, 'message_int': message_int})


@app.route('/decrypt-rsa', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message = data.get('encrypted_message')
    d = data.get('d')
    n = data.get('n')

    # Kiểm tra dữ liệu đầu vào
    if not encrypted_message or not n or not d:
        return jsonify({"error": "Missing data"}), 400
    
    try:
        decrypted_message = rsa_backend.decrypt_message(int(encrypted_message), (int(n), int(d)))
        return jsonify({'decrypted_message': decrypted_message})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/sign-rsa', methods=['POST'])
def sign():
    data = request.json
    p = data['p']
    q = data['q']
    e = data['e']
    n = p * q
    phi_n = (p - 1) * (q - 1)
    message = data['message']
    
    # Hashing the message
    hashed_message = rsa_backend.hash_message(message)
    
    # Generate RSA keys
    private_key, public_key = rsa_backend.generate_rsa_keys(n, phi_n, e)
    
    # Encrypt the message
    encrypted_message = rsa_backend.encrypt_message(message, public_key)
    
    # Decrypt the message
    decrypted_message = rsa_backend.decrypt_message(encrypted_message, private_key)
    
    # Sign the message
    signature = rsa_backend.sign_message(message, private_key)
    
    # Verify the signature
    v = rsa_backend.mod_exp(signature, public_key[1], n)
    
    return jsonify({
        'encrypted_message': encrypted_message,
        'signature': signature,
        'hashed_message': hashed_message,
        'public_key': public_key,
        'private_key': private_key,
        'decrypt_message': decrypted_message,
        'V': v
    })

#@app.route('/tên API', methods=['POST'])
@app.route('/calculate_alpha', methods=['POST'])
def calculate():
    data = request.json
    p = data.get('p')
    if not p:
        return jsonify({"error": "Missing parameter 'p'"}), 400

    try:
        alpha = elgammal_backend.primitive_root(p)
        return jsonify({"alpha": alpha})
    except ValueError:
        return jsonify({"error": "No primitive root for given p"}), 400

# Tính beta
@app.route('/calculate_beta', methods=['POST'])
def calculate_beta():
    data = request.json
    p = data.get('p')
    alpha = data.get('alpha')
    a = data.get('a')
    if not all([p, alpha, a]):
        return jsonify({"error": "Missing parameters 'p', 'alpha', or 'a'"}), 400

    try:
        beta = pow(alpha, a, p)
        return jsonify({"beta": beta})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Băm message
@app.route('/hash_message_elgamal', methods=['POST'])
def hash_message():
    data = request.json
    message = data.get('message')
    if not message:
        return jsonify({"error": "Missing parameter 'message'"}), 400

    def hashing(txt):
        ans = 0
        for c in txt:
            ans = ans * 26 + (ord(c) - ord('A'))
        return ans

    hashed_message = hashing(message)
    return jsonify({"hashed_message": hashed_message})

# Mã hóa ElGamal
@app.route('/encrypt_elgammal', methods=['POST'])
def encrypt_elgammal():
    data = request.json
    p = data.get('p')
    alpha = data.get('alpha')
    beta = data.get('beta')
    k = data.get('k')
    message = data.get('message')

    if not all([p, alpha, beta, k, message]):
        return jsonify({"error": "Missing parameters 'p', 'alpha', 'beta', 'k', or 'message'"}), 400

    try:
        def hashing(txt):
            ans = 0
            for c in txt:
                ans = ans * 26 + (ord(c) - ord('A'))
            return ans

        hash_value = hashing(message)
        y1 = pow(alpha, k, p)
        y2 = (hash_value * pow(beta, k, p)) % p
        return jsonify({"encrypted_message": (y1, y2)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Giải mã ElGamal
@app.route('/decrypt_elgammal', methods=['POST'])
def decrypt_elgammal():
    data = request.json
    p = data.get('p')
    alpha = data.get('alpha')
    a = data.get('a')
    encrypted_message = data.get('encrypted_message')

    if not all([p, alpha, a, encrypted_message]):
        return jsonify({"error": "Missing parameters 'p', 'alpha', 'a', or 'encrypted_message'"}), 400

    try:
        y1, y2 = encrypted_message
        decrypted_message = (y2 * pow(y1, p - a - 1, p)) % p
        return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

##
#Elgammal signature
##
# # Endpoint 1: Tính alpha nguyên thủy của p
# @app.route('/caculate_alpha_elgamalSign', methods=['POST'])
# def calculate_alpha():
#     data = request.get_json()
#     p = int(data['p'])
#     alpha = elgammal_backend.primitive_root(p)
#     return jsonify({'p': p, 'alpha': alpha})

# # Endpoint 2: Hash message và tạo signature SHA-512
# @app.route('/hashed_message_elgamalSign', methods=['POST'])
# def hash_message_endpoint():
#     data = request.get_json()
#     message = data['message']
    
#     hashed_message = elgammal_backend.hashing(message)
#     sha512_signature = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    
#     return jsonify({
#         'hashed_message': hashed_message,
#         'sha512_signature': sha512_signature
#     })

# # Endpoint 3: Mã hóa thông điệp và chữ ký
# @app.route('/encrypt_elgamalSign', methods=['POST'])
# def encrypt_elgamal():
#     data = request.get_json()
#     p = int(data['p'])
#     alpha = int(data['alpha'])
#     a = int(data['a'])
#     beta = pow(alpha, a, p)
#     message = data['message']
    
#     # Mã hóa chữ ký
#     hash_value = int(hashlib.sha512(message.encode()).hexdigest(), 16)
#     k = 3  # Chọn ngẫu nhiên một số nhỏ cho đơn giản
#     gamma = pow(alpha, k, p)
#     delta = (hash_value - a * gamma) * pow(k, -1, p - 1) % (p - 1)
    
#     encrypted_signature = (gamma, delta)
    
#     return jsonify({
#         'p': p,
#         'alpha': alpha,
#         'beta': beta,
#         'encrypted_signature': encrypted_signature
#     })

# # Endpoint 4: Giải mã thông điệp và chữ ký
# @app.route('/decrypt_elgamalSign', methods=['POST'])
# def decrypt_elgamal():
#     data = request.get_json()
#     p = int(data['p'])
#     alpha = int(data['alpha'])
#     a = int(data['a'])
#     beta = pow(alpha, a, p)
#     message = data['message']
    
#     # Kiểm tra chữ ký
#     hash_value = int(hashlib.sha512(message.encode()).hexdigest(), 16)
#     k = 3
#     gamma = pow(alpha, k, p)
#     delta = (hash_value - a * gamma) * pow(k, -1, p - 1) % (p - 1)
#     v1 = (pow(beta, gamma, p) * pow(gamma, delta, p)) % p
#     v2 = pow(alpha, hash_value, p)
    
#     valid = (pow(beta, gamma, p) * pow(gamma, delta, p)) % p == pow(alpha, hash_value, p)
    
#     return jsonify({
#         'v1': v1,
#         'v2': v2,
#         'decrypted_signature_valid': valid
#     })
    
@app.route('/sign_elgammal', methods=['POST'])
def sign_elgammal():
    data = request.get_json()
    p = int(data['p'])
    alpha = 2  # Giá trị nguyên thủy mặc định
    a = int(data['a'])  # Khóa bí mật (private key)
    message = data['message']
    
    # Tạo khóa công khai
    beta = rsa_backend.mod_exp(alpha, a, p)
    
    # Băm thông điệp
    hash_value = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    
    # Chọn k ngẫu nhiên sao cho gcd(k, p-1) = 1
    k = random.randint(2, p-2)
    while rsa_backend.gcd(k, p-1) != 1:
        k = random.randint(2, p-2)
    
    # Tính gamma và delta cho chữ ký
    gamma = rsa_backend.mod_exp(alpha, k, p)
    k_inv = pow(k, -1, p-1)
    delta = (k_inv * (hash_value - a * gamma)) % (p - 1)
    signature = [gamma, delta]
    
    # Mã hóa thông điệp
    y1 = rsa_backend.mod_exp(alpha, k, p)
    y2 = (hash_value * rsa_backend.mod_exp(beta, k, p)) % p
    encrypted_message = [y1, y2]
    
    # Giải mã thông điệp
    decrypted_hash = (y2 * rsa_backend.mod_exp(y1, p-1-a, p)) % p
    
    # Xác minh chữ ký
    v1 = (rsa_backend.mod_exp(beta, gamma, p) * rsa_backend.mod_exp(gamma, delta, p)) % p
    v2 = rsa_backend.mod_exp(alpha, hash_value, p)
    valid = v1 == v2
    
    return jsonify({
        'alpha': alpha,
        'private_key': a,
        'public_key': beta,
        'signature': signature,
        'encrypted_message': encrypted_message,
        'decrypted_hash': decrypted_hash,
        'valid': valid,
        'v1': v1,
        'v2': v2,
        'k': k,
    })

    
#ELLIPTIC_CURVE
@app.route('/check_condition', methods=['POST'])
def check_condition_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    
    is_valid = elliptic_backend.check_curve_conditions(a, b, p)

    # Return the result with a "valid" key in the response
    return jsonify({
        "valid": is_valid,
        "status": "success" if is_valid else "error",
        "message": "Condition is valid." if is_valid else "Condition is not valid."
    })
@app.route('/random_G', methods=['POST'])
def random_G_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    
    point = elliptic_backend.get_random_point_on_curve(a, b, p)
    return jsonify({"status": "success", "point": point})

@app.route('/check_G', methods=['POST'])
def check_G_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    # G là một tuple (x, y)
    G = [data.get('x'), data.get('y')]
    
    if elliptic_backend.is_point_valid(a, b, p, G):
        return jsonify({"status": True, "message": "Point belongs to the elliptic curve."})
    else:
        return jsonify({"status": False, "message": "Point does not belong to the elliptic curve."})

@app.route('/caculate_order', methods=['POST'])
def caculate_order_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    G = [data.get('x'), data.get('y')]
    
    order = elliptic_backend.calculate_order_of_point(a, b, p, G)
    return jsonify({"order": order})

# Tạo cặp khóa công khai và khóa bí mật
@app.route('/generate_key', methods=['POST'])
def generate_key_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    G = [data.get('x'), data.get('y')]  # Điểm cơ sở G
    n = data.get('n')
    s = data.get('s')
    
    private_key, public_key= elliptic_backend.generate_keys(a, b, p, G, n, s)
    return jsonify({
        "status": "success",
        "public_key": public_key,
        "private_key": private_key,
    })

@app.route('/message_to_point', methods=['POST'])
def message_to_point_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    message = data.get('message')
    x, y = elliptic_backend.map_message_to_curve(a, b, p, message)
    return jsonify({"status": "success", "x": x, "y": y})

# Mã hóa thông điệp

@app.route('/get_points', methods=['GET'])
def get_points():
    # Lấy tham số a, b, p từ query parameters
    a = int(request.args.get('a'))  # Giá trị mặc định của a là 2 nếu không có tham số
    b = int(request.args.get('b'))  # Giá trị mặc định của b là 3 nếu không có tham số
    p = int(request.args.get('p'))  # Giá trị mặc định của p là 17 nếu không có tham số

    points = elliptic_backend.get_points_on_curve(a, b, p)  # Lấy các điểm từ đường cong elliptic
    return jsonify(points)  # Trả về dưới dạng JSON

@app.route('/encrypt-elip', methods=['POST'])
def encrypt_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    message = data.get('message')
    G = data.get('G')
    n = data.get('n')
    k = data.get('k')  # Số ngẫu nhiên k
    
    C1, C2 = elliptic_backend.encrypt_message(a, b, p, G, n, message, k)
    return jsonify({
        "status": "success",
        "C1": C1,
        "C2": C2
    })

# Giải mã thông điệp
@app.route('/decrypt-elip', methods=['POST'])
def decrypt_api():
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    G = data.get('G')
    n = data.get('n')
    s = data.get('s')
    C1 = [data.get('C1x'), data.get('C1y')]
    C2 = [data.get('C2x'), data.get('C2y')]
    encrypted_message = [C1, C2]
    
    decrypted_message = elliptic_backend.decrypt_message(a, b, p, G, n, encrypted_message, s)
    return jsonify({
        "status": "success",
        "decrypted_message": decrypted_message
    })
    
@app.route('/sign_elip', methods=['POST'])
def sign_elip():
    # Lấy dữ liệu từ request
    data = request.get_json()
    p = data.get('p')
    a = data.get('a')
    b = data.get('b')
    message = data.get('message')
    Gx = data.get('Gx')
    Gy = data.get('Gy')
    d = data.get('d')  # Khóa riêng
    G = [Gx, Gy]  # Điểm G

    # Tính toán order của điểm G
    n = elliptic_backend.calculate_order_of_point(a, b, p, G)

    # Băm thông điệp
    hashed_message = rsa_backend.hash_message(message)

    # Tạo chữ ký số
    k = 2  # Giá trị ngẫu nhiên k
    signature = elliptic_backend.sign_message(a, b, p, G, n, hashed_message, k, d)

    # Mã hóa thông điệp
    C1, C2 = elliptic_backend.encrypt_message(a, b, p, G, n, message, k)

    # Lấy khóa công khai và riêng tư (giả sử đã triển khai hàm này)
    private_key, public_key  = elliptic_backend.generate_keys(a, b, p, G, n, d)

    # Giải mã thông điệp để kiểm tra
    decrypted_message = elliptic_backend.decrypt_message(a, b, p, G, n, (C1, C2), d)

    # Xác thực chữ ký
    v, w, u1, u2, P = elliptic_backend.verify_signature(
        a, b, p, G, n, message, hashed_message, signature, public_key
    )

    # Trả về JSON response
    return jsonify({
        "hashed_message": hashed_message,
        "signature": signature,
        "C1": C1,
        "C2": C2,
        "public_key": public_key,
        "private_key": private_key,
        "decrypted_message": decrypted_message,
        "n": n,
        "v": v,
        "w": w,
        "u1": u1,
        "u2": u2,
        "P": P
    })
##
#EUCLID
##
@app.route("/euclid2", methods=["POST"])  # Cho phép phương thức POST
def euclid2():
    data = request.get_json()
    if not data or "number1" not in data or "number2" not in data:
        return jsonify({"error": "Missing required parameters"}), 400

    number1 = data["number1"]
    number2 = data["number2"]

    # Tính UCLN
    while number2 != 0:
        number1, number2 = number2, number1 % number2

    return jsonify({"UCLN": number1})


@app.route("/extended_euclid", methods=["POST"])  # Cho phép phương thức POST
def extended_euclid():
    data = request.get_json()
    if not data or "number1" not in data or "number2" not in data:
        return jsonify({"error": "Missing required parameters"}), 400

    number1 = data["number1"]
    number2 = data["number2"]

    # Tính UCLN và các hệ số Bezout
    def gcd_extended(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = gcd_extended(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    gcd, x, y = gcd_extended(number1, number2)
    return jsonify({"UCLN": gcd, "x": x, "y": y})

##
#Primaly
##
def aks_prime_check(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

@app.route("/prime_check", methods=["POST"])
def prime_check():
    data = request.get_json()
    number = data.get('number')
    
    if aks_prime_check(number):
        return jsonify({"is_prime": True})
    else:
        return jsonify({"is_prime": False})
    
@app.route("/prime_generation", methods=["POST"])
def prime_generation():
    data = request.get_json()
    a = data.get('a')
    b = data.get('b')
    
    # Hàm tìm số nguyên tố trong khoảng [a, b]
    def generate_prime_in_range(a, b):
        while True:
            num = random.randint(a, b)
            if aks_prime_check(num):
                return num
    
    prime_number = generate_prime_in_range(a, b)
    
    return jsonify({"prime_number": prime_number})
if __name__ == '__main__':
    app.run(debug=True)
