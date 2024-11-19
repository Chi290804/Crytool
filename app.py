from flask import Flask, request, jsonify, render_template
import rsa_backend as rsa_backend
 
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

@app.route('/encrypt', methods=['POST'])
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

if __name__ == '__main__':
    app.run(debug=True)
