from flask import Flask, request, jsonify, render_template
import rsa_backend as rsa_backend
import elgammal_backend as elgammal_backend
import elliptic_backend as elliptic_backend
 
app = Flask(__name__)


@app.route('/')
def rsa():
    return render_template('rsa_screen.html')

@app.route('/elgammal')
def elgammal():
    return render_template('elgammal.html')

@app.route('/elliptic')
def elliptic():
    return render_template('elliptic.html')

@app.route('/euclid')
def euclid():
    return render_template('euclid.html')

@app.route('/primality')
def primality():
    return render_template('primality.html')


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

    public_key = tuple(data.get('public_key'))
    
    # Gọi hàm mã hóa
    try:
        encrypted_message = rsa_backend.encrypt_message(message, public_key)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({'encrypted_message': encrypted_message})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message = int(data['encrypted_message'])
    private_key = tuple(data['private_key'])
    
    decrypted_message = rsa_backend.decrypt_message(encrypted_message, private_key)
    return jsonify({'decrypted_message': decrypted_message})

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
@app.route('/hash_message', methods=['POST'])
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
    encrypted_message = (data.get('C1'), data.get('C2'))
    
    decrypted_message = elliptic_backend.decrypt_message(a, b, p, G, n, encrypted_message, s)
    return jsonify({
        "status": "success",
        "decrypted_message": decrypted_message
    })

if __name__ == '__main__':
    app.run(debug=True)
