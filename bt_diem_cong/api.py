import os
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

# Các thư viện phục vụ DH Key Pair
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_lab04'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- KHỞI TẠO DỮ LIỆU AES-RSA SOCKET ---
# Sinh key cho RSA Server cố định khi khởi động api.py
SERVER_RSA_KEY = RSA.generate(2048)
# Lưu trữ thông tin kết nối client: { sid: { 'username': ..., 'aes_key': ... } }
connected_clients = {}

# --- KHỞI TẠO DỮ LIỆU DH KEY PAIR ---
DH_PEM_PATH = os.path.join(os.path.dirname(__file__), 'dh_key_pair', 'server_public_key.pem')

def init_dh_server():
    # Tạo thư mục dh_key_pair nếu chưa có để tránh lỗi lưu file pem
    os.makedirs(os.path.dirname(DH_PEM_PATH), exist_ok=True)
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    with open(DH_PEM_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Tạo sẵn file PEM của server
init_dh_server()


# ================= ROUTES (ĐIỀU HƯỚNG WEB) =================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aes-rsa-client')
def aes_rsa_client():
    return render_template('aes_rsa_socket_client.html')

@app.route('/aes-rsa-server')
def aes_rsa_server():
    return render_template('aes_rsa_socket_server.html')

@app.route('/dh-client')
def dh_client():
    return render_template('dh_key_pair_client.html')

@app.route('/dh-server')
def dh_server():
    return render_template('dh_key_pair_server.html')


# ================= SOCKETIO LOGIC (AES-RSA CHAT) =================

@socketio.on('client_join')
def handle_join(data):
    sid = request.sid
    username = data.get('username', f"Client_{sid[:4]}")
    
    # --- MÔ PHỎNG HANDSHAKE TRÊN WEB ---
    # 1. Server sinh khóa AES riêng cho Client này
    client_aes_key = get_random_bytes(16)
    
    # 2. Lưu trạng thái client vào bộ nhớ server
    connected_clients[sid] = {
        'username': username,
        'aes_key': client_aes_key
    }
    
    # Thông báo cho giao diện Server biết có kết nối mới kèm theo logs kĩ thuật
    socketio.emit('server_log', {
        'type': 'connect',
        'message': f"[{username}] đã kết nối.",
        'aes_key_hex': binascii.hexlify(client_aes_key).decode()
    }, to='server_room')

    # Join rooms
    join_room('chat_room')
    
    # Gửi thông báo đến tất cả các Client khác
    emit('chat_notification', {'message': f"{username} đã tham gia vào đoạn chat"}, to='chat_room', include_self=False)

@socketio.on('join_server_dashboard')
def handle_server_join():
    # Đăng ký riêng tab Server vào một room để nhận log kĩ thuật mã hóa
    join_room('server_room')

@socketio.on('send_msg')
def handle_message(data):
    sid = request.sid
    if sid not in connected_clients:
        return
    
    username = connected_clients[sid]['username']
    aes_key = connected_clients[sid]['aes_key']
    raw_text = data.get('message', '')
    
    # --- MÔ PHỎNG QUÁ TRÌNH MÃ HÓA/GIẢI MÃ ---
    # Mã hóa text thô bằng AES theo chuẩn CBC cũ của bạn
    cipher_encrypt = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_encrypt.iv
    ciphertext = cipher_encrypt.encrypt(pad(raw_text.encode(), AES.block_size))
    encrypted_payload_hex = binascii.hexlify(iv + ciphertext).decode()
    
    # Gửi log mã hóa này lên màn hình Server hiển thị
    socketio.emit('server_log', {
        'type': 'msg',
        'username': username,
        'raw_text': raw_text,
        'encrypted_hex': encrypted_payload_hex
    }, to='server_room')
    
    # Phát tán tin nhắn tới các client khác (Mô phỏng: Server giải mã ra text thô rồi encrypt lại bằng key của client nhận)
    # Để đơn giản và trực quan trên Web, ta phát text thô kèm người gửi, các client nhận sẽ tự render.
    emit('receive_msg', {'username': username, 'message': raw_text}, to='chat_room', include_self=True)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in connected_clients:
        username = connected_clients[sid]['username']
        del connected_clients[sid]
        
        # Báo cho Server Dashboard
        socketio.emit('server_log', {'type': 'disconnect', 'message': f"[{username}] đã thoát."}, to='server_room')
        # Báo cho các Client còn lại
        socketio.emit('chat_notification', {'message': f"{username} đã rời khỏi đoạn chat."}, to='chat_room')


# ================= AJAX/SOCKET FOR DH KEY PAIR =================

@app.route('/api/dh/get-server-public')
def get_dh_server_public():
    if os.path.exists(DH_PEM_PATH):
        with open(DH_PEM_PATH, 'r') as f:
            pem_data = f.read()
        return {'status': 'success', 'pem': pem_data}
    return {'status': 'error', 'message': 'File không tồn tại.'}, 404

@socketio.on('dh_client_computed')
def handle_dh_client_computed(data):
    # Nhận dữ liệu thông báo từ client khi tính toán xong Shared secret để đẩy lên màn hình Server DH xem
    socketio.emit('dh_server_log', data, to='dh_server_room')

@socketio.on('join_dh_server')
def handle_dh_server_join():
    join_room('dh_server_room')





# --- HÀM MAIN CHẠY FLASK APP ---
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5050, debug=True)