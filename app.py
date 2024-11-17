from flask import Flask, request, jsonify, render_template
import rsa_backend as rsa_backend
 
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('rsa_screen.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    p = int(data['p'])
    q = int(data['q'])
    
    private_key, public_key = rsa_backend.generate_rsa_keys(p, q)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    return jsonify({
        'n': n,
        'phi_n': phi_n,
        'public_key': public_key,
        'private_key': private_key
    })

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data['message']
    public_key = tuple(data['public_key'])
    
    encrypted_message = rsa_backend.encrypt_message(message, public_key)
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
