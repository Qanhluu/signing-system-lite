import os
import json
import base64
import hashlib
import datetime
from flask import Flask, request, jsonify, session, send_file, abort
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'chuyen-gia-bao-mat-30-nam-v2'

UPLOAD_FOLDER = 'uploads'
DB_FILE = 'database.json'
HTML_FILE = 'index.html'

def init_system():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    if not os.path.exists(DB_FILE):
        db_template = {
            "users": [
                {"id": 1, "username": "admin", "password": "123", "role": "admin", "public_key": "", "private_key": "", "can_upload": True, "can_edit": True},
                {"id": 2, "username": "user1", "password": "123", "role": "user", "public_key": "", "private_key": "", "can_upload": False, "can_edit": False}
            ],
            "documents": [], "logs": [], "requests": []
        }
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(db_template, f, indent=4)

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4)

def load_db():
    with open(DB_FILE, 'r', encoding='utf-8') as f: db = json.load(f)
    return db

def add_log(user_id, action):
    db = load_db()
    db['logs'].append({
        "user_id": user_id, "action": action, 
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_db(db)

def gen_rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
    return priv_pem, pub_pem

# --- AUTH ---
@app.route('/')
def index(): return send_file(HTML_FILE)

@app.route('/api/login', methods=['POST'])
def login():
    data, db = request.json, load_db()
    for user in db['users']:
        if user['username'] == data.get('username') and user['password'] == data.get('password'):
            if not user.get('public_key'): 
                priv, pub = gen_rsa_keys()
                user['private_key'], user['public_key'] = priv, pub
                save_db(db)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            add_log(user['id'], f"Đăng nhập hệ thống")
            return jsonify({"msg": "OK", "role": user['role'], "id": user['id']})
    return jsonify({"error": "Sai tài khoản hoặc mật khẩu"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"msg": "OK"})

# --- REQUESTS & UPLOAD ---
@app.route('/api/requests', methods=['GET', 'POST'])
def handle_requests():
    if 'user_id' not in session: return abort(401)
    db = load_db()
    if request.method == 'POST':
        req_type = request.json.get('type')
        db['requests'].append({
            "id": len(db['requests']) + 1, "user_id": session['user_id'], "username": session['username'],
            "type": req_type, "status": "Chờ duyệt", "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_db(db)
        return jsonify({"msg": "Đã gửi yêu cầu"})
    return jsonify(db['requests'])

@app.route('/api/requests/<int:req_id>/approve', methods=['POST'])
def approve_request(req_id):
    if session.get('role') != 'admin': return abort(403)
    db = load_db()
    req = next((r for r in db['requests'] if r['id'] == req_id), None)
    if req:
        req['status'] = 'Đã duyệt'
        user = next(u for u in db['users'] if u['id'] == req['user_id'])
        if req['type'] == 'upload': user['can_upload'] = True
        elif req['type'] == 'edit_doc': user['can_edit'] = True
        save_db(db)
    return jsonify({"msg": "OK"})

@app.route('/api/upload', methods=['POST'])
def upload():
    db = load_db()
    
    user = next((u for u in db['users'] if u['id'] == session.get('user_id')), None)
    if not user: return abort(401)

    if session.get('role') != 'admin' and not user.get('can_upload'): 
        return jsonify({"error": "Bạn chưa được cấp quyền upload"}), 403
        
    file = request.files['file']
    if not file: return jsonify({"error": "Không có file nào được chọn"}), 400

    raw_custom_name = request.form.get('custom_name', '').strip()
    if raw_custom_name:
        filename = secure_filename(raw_custom_name)
    else:
        filename = secure_filename(file.filename)

    ext = os.path.splitext(file.filename)[1]
    if not filename.endswith(ext): 
        filename += ext

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    file.save(filepath)
    with open(filepath, 'rb') as f: 
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    db['documents'].append({
        "id": len(db['documents']) + 1, 
        "filename": filename, 
        "filepath": filepath,
        "original_hash": file_hash, 
        "owner_id": session['user_id'], 
        "uploader_name": session['username'], 
        "upload_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Chưa ký", 
        "is_approved": False, 
        "signatures": [] 
    })
    save_db(db)
    add_log(session['user_id'], f"Upload: {filename}")
    return jsonify({"msg": "OK"})

# --- DOCUMENTS ---
@app.route('/api/documents', methods=['GET'])
def get_docs():
    if 'user_id' not in session: return jsonify({"error": "Auth"}), 401
    db = load_db()
    for doc in db['documents']:
        if os.path.exists(doc['filepath']):
            with open(doc['filepath'], 'rb') as f:
                if hashlib.sha256(f.read()).hexdigest() != doc['original_hash']: doc['status'] = 'Bị chỉnh sửa'
    save_db(db)
    docs = db['documents']
    if session.get('role') != 'admin':
        docs = [d for d in docs if d['is_approved'] or d['owner_id'] == session['user_id']]
    return jsonify(docs)

@app.route('/api/documents/<int:doc_id>/approve', methods=['POST'])
def approve_doc(doc_id):
    if session.get('role') != 'admin': return abort(403)
    db = load_db()
    doc = next((d for d in db['documents'] if d['id'] == doc_id), None)
    if doc:
        doc['is_approved'] = True
        save_db(db)
    return jsonify({"msg": "OK"})

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
def get_doc_detail(doc_id):
    if 'user_id' not in session: return abort(401)
    db = load_db()
    doc = next((d for d in db['documents'] if d['id'] == doc_id), None)
    if not doc: return abort(404)
    
    # Kiểm tra quyền xem file
    is_owner = doc['owner_id'] == session['user_id']
    is_admin = session.get('role') == 'admin'
    if not (is_admin or doc['is_approved'] or is_owner):
        return jsonify({"error": "Bạn không có quyền xem tài liệu này"}), 403

@app.route('/api/view/<int:doc_id>')
def view_file(doc_id):
    doc = next((d for d in load_db()['documents'] if d['id'] == doc_id), None)
    return send_file(doc['filepath'], as_attachment=False)

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
def delete_doc(doc_id):
    if session.get('role') != 'admin': return abort(403)
    db = load_db()
    doc = next((d for d in db['documents'] if d['id'] == doc_id), None)
    if doc:
        if os.path.exists(doc['filepath']): os.remove(doc['filepath'])
        db['documents'] = [d for d in db['documents'] if d['id'] != doc_id]
        save_db(db)
    return jsonify({"msg": "OK"})

# --- SIGN & VERIFY ---
@app.route('/api/sign', methods=['POST'])
def sign():
    db, doc_id = load_db(), request.json.get('id')
    user = next(u for u in db['users'] if u['id'] == session['user_id'])
    doc = next(d for d in db['documents'] if d['id'] == doc_id)
    
    if any(sig['user_id'] == user['id'] for sig in doc.get('signatures', [])):
        return jsonify({"error": "Bạn đã ký văn bản này rồi!"}), 400
        
    priv_key = serialization.load_pem_private_key(user['private_key'].encode(), password=None)
    with open(doc['filepath'], 'rb') as f: file_data = f.read()
    
    signature = priv_key.sign(file_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    
    doc['signatures'].append({
        "user_id": user['id'], "username": user['username'],
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "signature_value": base64.b64encode(signature).decode('utf-8')
    })
    doc['status'] = 'Đã ký'
    save_db(db)
    add_log(user['id'], f"Ký số văn bản: {doc['filename']}")
    return jsonify({"msg": "Ký thành công"})

@app.route('/api/revoke_sign', methods=['POST'])
def revoke_sign():
    db, doc_id = load_db(), request.json.get('id')
    doc = next((d for d in db['documents'] if d['id'] == doc_id), None)
    if doc:
        original_len = len(doc['signatures'])
        doc['signatures'] = [s for s in doc['signatures'] if s['user_id'] != session['user_id']]
        if len(doc['signatures']) < original_len:
            if len(doc['signatures']) == 0: doc['status'] = 'Chưa ký'
            save_db(db)
            add_log(session['user_id'], f"Thu hồi chữ ký: {doc['filename']}")
            return jsonify({"msg": "Đã thu hồi chữ ký thành công!"})
    return jsonify({"error": "Lỗi hệ thống hoặc bạn chưa ký!"}), 400

@app.route('/api/verify', methods=['POST'])
def verify():
    db, doc_id = load_db(), request.json.get('id')
    doc = next(d for d in db['documents'] if d['id'] == doc_id)
    
    if not doc.get('signatures'): return jsonify({"message": "Chưa có chữ ký!"})
    
    with open(doc['filepath'], 'rb') as f: data = f.read()
    if hashlib.sha256(data).hexdigest() != doc['original_hash']:
        doc['status'] = 'Bị chỉnh sửa'; save_db(db)
        return jsonify({"message": "❌ CẢNH BÁO: Hash không khớp. VĂN BẢN ĐÃ BỊ SỬA ĐỔI!"})

    all_valid = True
    results = []
    for sig in doc['signatures']:
        signer = next((u for u in db['users'] if u['id'] == sig['user_id']), None)
        if not signer: 
            all_valid = False
            continue
        pub_key = serialization.load_pem_public_key(signer['public_key'].encode())
        try: 
            pub_key.verify(base64.b64decode(sig['signature_value']), data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            results.append(f"✔ Chữ ký của [{sig['username']}] HỢP LỆ")
        except Exception: 
            all_valid = False
            results.append(f"❌ Chữ ký của [{sig['username']}] KHÔNG HỢP LỆ")
            
    doc['status'] = 'Hợp lệ' if all_valid else 'Chữ ký không hợp lệ'
    save_db(db)
    add_log(session['user_id'], f"Xác thực văn bản: {doc['filename']} ({doc['status']})")
    
    final_msg = "✅ TẤT CẢ CHỮ KÝ HỢP LỆ." if all_valid else "❌ CÓ CHỮ KÝ KHÔNG HỢP LỆ!"
    return jsonify({"message": final_msg + "\n\n" + "\n".join(results)})

# --- ADMIN USER MANAGEMENT ---
@app.route('/api/users', methods=['GET', 'POST'])
def manage_users():
    if session.get('role') != 'admin': return abort(403)
    db = load_db()
    if request.method == 'GET':
        return jsonify([{
            "id": u["id"], "username": u["username"], "role": u["role"], 
            "can_upload": u.get("can_upload", False), "can_edit": u.get("can_edit", False)
        } for u in db['users']])
    
    data = request.json
    priv, pub = gen_rsa_keys()
    db['users'].append({"id": len(db['users']) + 1, "username": data['username'], "password": data['password'], "role": data['role'], "public_key": pub, "private_key": priv, "can_upload": True if data['role'] == 'admin' else False, "can_edit": True if data['role'] == 'admin' else False})
    save_db(db)
    return jsonify({"msg": "OK"})

@app.route('/api/users/<int:user_id>/revoke', methods=['POST'])
def revoke_user_permission(user_id):
    if session.get('role') != 'admin': return abort(403)
    perm = request.json.get('perm') 
    db = load_db()
    user = next((u for u in db['users'] if u['id'] == user_id), None)
    if user:
        if perm == 'upload': user['can_upload'] = False
        elif perm == 'edit_doc': user['can_edit'] = False
        
        for req in db['requests']:
            if req['user_id'] == user_id and req['status'] == 'Đã duyệt' and req['type'] == perm:
                req['status'] = 'Đã thu hồi quyền'
                
        save_db(db)
        add_log(session['user_id'], f"Thu hồi quyền {perm} của User: {user['username']}")
        return jsonify({"msg": f"Đã thu hồi quyền thành công!"})
    return abort(404)

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if session.get('role') != 'admin': return abort(403)
    if user_id == session['user_id']: return jsonify({"error": "Admin không thể tự xóa chính mình"}), 400
    db = load_db()
    db['users'] = [u for u in db['users'] if u['id'] != user_id]
    save_db(db)
    return jsonify({"msg": "OK"})

@app.route('/api/logs', methods=['GET'])
def get_logs(): return jsonify(load_db().get('logs', [])[::-1])

@app.route('/api/documents/<int:doc_id>/edit', methods=['POST'])
def edit_document(doc_id):
    if 'user_id' not in session: return abort(401)
    
    db = load_db()
    user = next(u for u in db['users'] if u['id'] == session['user_id'])
    
    # Kiểm tra quyền chỉnh sửa
    if not user.get('can_edit'):
        return jsonify({"error": "Bạn không có quyền chỉnh sửa văn bản"}), 403
        
    doc = next((d for d in db['documents'] if d['id'] == doc_id), None)
    if not doc: return abort(404)

    # Nhận nội dung mới từ Frontend (giả sử là text/html hoặc markdown)
    new_content = request.json.get('content')
    
    # Ghi đè vào file vật lý
    with open(doc['filepath'], 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    # CẬP NHẬT QUAN TRỌNG: 
    # Vì file đã sửa, các chữ ký cũ không còn giá trị.
    # Ta phải xóa chữ ký cũ và cập nhật lại Hash gốc.
    with open(doc['filepath'], 'rb') as f:
        new_hash = hashlib.sha256(f.read()).hexdigest()
    
    doc['original_hash'] = new_hash
    doc['signatures'] = [] # Xóa chữ ký cũ vì nội dung đã đổi
    doc['status'] = 'Chưa ký'
    
    save_db(db)
    add_log(session['user_id'], f"Chỉnh sửa nội dung file: {doc['filename']}")
    return jsonify({"msg": "Cập nhật thành công, vui lòng ký lại văn bản!"})

if __name__ == '__main__':
    init_system()
    app.run(debug=True, port=5000)