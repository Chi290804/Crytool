import hashlib
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

def hash_message(message):
      # Băm thông điệp bằng SHA-256
    hash_object = hashlib.sha256(message.encode())
    return int.from_bytes(hash_object.digest(), 'big')

def sign_message(message, private_key):
    n, d = private_key
    hashed_message = hash_message(message)
    print(f"hashed_message: {hashed_message}")
    signature = mod_exp(hashed_message, d, n)
    return signature

def verify_message(signature, message, public_key):
    n, e = public_key
    print(f"1. Bắt đầu xác minh chữ ký cho thông điệp: '{message}'")
    
    # Bước 1: Băm thông điệp
    hM = hash_message(message)
    print(f"2. Băm thông điệp bằng SHA-256, giá trị băm h(M) = {hM}")
    
    # Bước 2: Giải mã chữ ký bằng khóa công khai (n, e)
    verified = mod_exp(signature, e, n)
    print(f"3. Giải mã chữ ký với e = {e} và n = {n}, thu được giá trị: {verified}")
    
    # Bước 3: So sánh giá trị băm của thông điệp và giá trị đã giải mã
    print(f"4. So sánh giá trị băm h(M) với giá trị đã giải mã:")
    if hM == verified:
        print("5. Chữ ký hợp lệ (h(M) == verified).")
        return True
    else:
        print("5. Chữ ký không hợp lệ (h(M) != verified).")
        return False

# Hàm main để kiểm tra các chức năng
# def main():
#     # Các tham số giả định cho RSA
#     p = 27169946228625259547471192772987564682653628818049108614686155180616358671971192192357418636359252855017002811496675719600679817573509624101951464145600845373888915622720022539825922294836177685587286545965224727797986121427289945387953455466785638705211916410795035614355134896529329427593251527948681591127
#     q = 28614067295713041335834982440918892930920454588097960047059399622908859176792035728565179894899780085826481899938858990689934235759873476495026490062929461947256629510502419808142369636410518283688516348683636240994472917137967158214858615878173964607442222364979676344543373246143706954828683491842492173483
#     e = 3917625637285712224869106845520840669030227309330572309625012253569441563591905241420372621636051635088862955282825055811360540917488908516960580447922156537062427132930791052831501210298936415421351938056240156338189162115219366681079718135870608493887560653219315575184609206029551759940254176330716274070664478359183820268398751871216818194293348655305182646148864108221552635752245883676553010602132564396156605513699480182637529335133900273687193733228797834949626856276230838592029402712457707039493231481389131994064226818127107580765284314330099061709673424120238209772145363617723054884339188565550441995  # Số công khai (phải là số nguyên tố đối với (p-1)*(q-1))

#     # Tính toán n và phi(n)
#     n = p * q
#     phi_n = (p - 1) * (q - 1)

#     # Tạo khóa RSA
#     private_key, public_key = generate_rsa_keys(n, phi_n, e)
    
#     # Thông điệp cần ký
#     message = "Hello Alice"

#     # Ký thông điệp
#     signature = sign_message(message, private_key)
#     print(f"Signature: {signature}")

#     # Xác minh chữ ký
#     is_valid = verify_message(signature, message, public_key)
#     print(f"Is the signature valid? {is_valid}")

# # Gọi hàm main để kiểm tra
# if __name__ == "__main__":
#     main()