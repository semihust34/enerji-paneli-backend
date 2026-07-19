from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import os
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# CORS'u daha geniş ve kesin tanımlayalım
# NOT: Authorization header ile Bearer token kullanıyoruz (cookie değil),
# bu yüzden supports_credentials'a gerek yok.
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Preflight (OPTIONS) isteklerini manuel olarak karşılayalım
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,ngrok-skip-browser-warning")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        return response, 200

# ---------------------------------------------------------------------
# JWT tabanlı oturum sistemi
# ÖNEMLİ: SECRET_KEY'i .env dosyanızda (Railway'de "Variables" sekmesinde)
# uzun, rastgele bir değer olarak tanımlayın: SECRET_KEY=... (örn. 40+ karakter).
# Tanımlanmazsa aşağıdaki varsayılan kullanılır ki bu PRODUCTION'DA GÜVENSİZDİR.
# ---------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "DEGISTIRILMESI-GEREKEN-GUVENSIZ-VARSAYILAN-ANAHTAR")
TOKEN_EXPIRY_HOURS = 12

def create_token(user_id, role, factories=None):
    payload = {
        "user_id": user_id,
        "role": role,
        "factories": factories or "",
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def token_required(allowed_roles=None):
    """Uç noktayı korur: geçerli bir Bearer token ister, verilirse role listesiyle sınırlar."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"success": False, "message": "Yetkilendirme başlığı eksik."}), 401
            token = auth_header.split(" ", 1)[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify({"success": False, "message": "Oturum süresi doldu, tekrar giriş yapın."}), 401
            except jwt.InvalidTokenError:
                return jsonify({"success": False, "message": "Geçersiz oturum."}), 401

            if allowed_roles and payload.get("role") not in allowed_roles:
                return jsonify({"success": False, "message": "Bu işlem için yetkiniz yok."}), 403

            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT")
    )

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password') 

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, role, company_name, accessible_factories FROM users WHERE username = %s AND plain_password = %s;",
            (username, password)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            user_id, role, company_name, factories = user
            token = create_token(user_id, role, factories)
            return jsonify({
                "success": True,
                "role": role,
                "token": token,
                "companyName": company_name,
                "factories": factories or ""
            }), 200
        else:
            return jsonify({"success": False, "message": "Kullanıcı adı veya şifre hatalı!"}), 401
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# NOT: Şifreler şu an veritabanında düz metin (plain_password) olarak
# tutuluyor ve öyle karşılaştırılıyor. Bunu değiştirmedim çünkü:
#  1) Bu oturumdan canlı Railway/Postgres veritabanınıza erişimim yok,
#     şema/veri migrasyonunu sizin çalıştırmanız gerekir.
#  2) customers.js/customer-management.html bilinçli olarak yöneticiye
#     mevcut şifreyi düz metin gösteriyor (bir "özellik" olarak) — tek
#     yönlü hash'e (werkzeug generate_password_hash) geçerseniz bu
#     görüntüleme özelliği kaybolur.
# Öneri: Gerçek ortama geçmeden önce ya bu "şifreyi göster" özelliğinden
# vazgeçip werkzeug.security.generate_password_hash/check_password_hash
# kullanın, ya da simetrik/geri döndürülebilir bir şifreleme (örn.
# cryptography kütüphanesinden Fernet) ekleyin. İsterseniz bu adımı da
# birlikte yapabiliriz.

@app.route('/api/customers', methods=['POST'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def add_customer():
    try:
        if request.json.get('role') == 'SUPERADMIN' and request.user.get('role') != 'SUPERADMIN':
            return jsonify({"success": False, "message": "Sadece Yönetici (SUPERADMIN) yeni bir Yönetici hesabı oluşturabilir."}), 403
        data = request.json
        password = data.get('password') 
        role = data.get('role', 'CUSTOMER') 
        factories = data.get('factories', '') # Gelen fabrikaları al

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (company_name, username, plain_password, role, accessible_factories) VALUES (%s, %s, %s, %s, %s) RETURNING id;",
            (data.get('company_name'), data.get('username'), password, role, factories)
        )
        new_user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "message": "Hesap başarıyla oluşturuldu!", "user_id": new_user_id}), 201
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "message": "Bu kullanıcı adı zaten sistemde kayıtlı!"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/customers', methods=['GET'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def get_customers():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, company_name, username, role, plain_password, accessible_factories FROM users ORDER BY id ASC;")
        users = cursor.fetchall()
        
        # factories verisini listeye ekledik
        user_list = [{"id": u[0], "company_name": u[1], "username": u[2], "role": u[3], "password": u[4] or "---", "factories": u[5] or ""} for u in users]
            
        cursor.close()
        conn.close()
        return jsonify({"success": True, "customers": user_list}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/customers/<int:user_id>', methods=['DELETE'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def delete_customer(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.user.get('role') != 'SUPERADMIN':
            cursor.execute("SELECT role FROM users WHERE id = %s;", (user_id,))
            target = cursor.fetchone()
            if target and target[0] == 'SUPERADMIN':
                cursor.close()
                conn.close()
                return jsonify({"success": False, "message": "Bir Yönetici (SUPERADMIN) hesabını silme yetkiniz yok."}), 403

        cursor.execute("DELETE FROM users WHERE id = %s RETURNING id;", (user_id,))
        deleted_id = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if deleted_id:
            return jsonify({"success": True, "message": "Kullanıcı başarıyla silindi."}), 200
        else:
            return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/customers/<int:user_id>', methods=['PUT'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def update_customer(user_id):
    try:
        data = request.json
        factories = data.get('factories', '') # Güncellenen fabrikaları al

        conn = get_db_connection()
        cursor = conn.cursor()

        if request.user.get('role') != 'SUPERADMIN':
            cursor.execute("SELECT role FROM users WHERE id = %s;", (user_id,))
            target = cursor.fetchone()
            if target and target[0] == 'SUPERADMIN':
                cursor.close()
                conn.close()
                return jsonify({"success": False, "message": "Bir Yönetici (SUPERADMIN) hesabını düzenleme yetkiniz yok."}), 403
            if data.get('role') == 'SUPERADMIN':
                cursor.close()
                conn.close()
                return jsonify({"success": False, "message": "Bir hesabı Yönetici (SUPERADMIN) rolüne yükseltme yetkiniz yok."}), 403

        cursor.execute("""
            UPDATE users 
            SET company_name = %s, username = %s, plain_password = %s, role = %s, accessible_factories = %s
            WHERE id = %s RETURNING id;
        """, (data.get('company_name'), data.get('username'), data.get('password'), data.get('role'), factories, user_id))
        
        updated_id = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if updated_id:
            return jsonify({"success": True, "message": "Kullanıcı başarıyla güncellendi."}), 200
        else:
            return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "message": "Bu kullanıcı adı zaten başka bir hesap tarafından kullanılıyor!"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# --- FABRİKA (TESİS) YÖNETİMİ UÇLARI ---

@app.route('/api/factories', methods=['POST'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def add_factory():
    try:
        data = request.json
        name = data.get('name')
        ip = data.get('ip')
        meter_count = data.get('meterCount', 0)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO factories (name, ip, meter_count) VALUES (%s, %s, %s) RETURNING id;",
            (name, ip, meter_count)
        )
        new_factory_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "message": "Fabrika başarıyla eklendi!", "id": new_factory_id}), 201
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/factories', methods=['GET'])
@token_required()  # herhangi bir rol (ADMIN/SUPERADMIN/CUSTOMER) erişebilir, aşağıda filtreleniyor
def get_factories():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, ip, meter_count FROM factories ORDER BY id ASC;")
        factories = cursor.fetchall()
        
        factory_list = [
            {"id": f[0], "name": f[1], "ip": f[2], "meterCount": f[3]} 
            for f in factories
        ]

        # Müşteri (CUSTOMER) rolü sadece kendisine tanımlı fabrikaları görebilir.
        # Erişim listesi, giriş sırasında token içine gömülmüş oluyor
        # (bkz. login içindeki accessible_factories -> create_token).
        if request.user.get('role') == 'CUSTOMER':
            allowed = {name.strip() for name in (request.user.get('factories') or '').split(',') if name.strip()}
            factory_list = [f for f in factory_list if f['name'] in allowed]

        cursor.close()
        conn.close()
        return jsonify({"success": True, "factories": factory_list}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/factories/<int:factory_id>', methods=['DELETE'])
@token_required(allowed_roles=['ADMIN', 'SUPERADMIN'])
def delete_factory(factory_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM factories WHERE id = %s RETURNING id;", (factory_id,))
        deleted_id = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if deleted_id:
            return jsonify({"success": True, "message": "Fabrika başarıyla silindi."}), 200
        else:
            return jsonify({"success": False, "message": "Fabrika bulunamadı."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Enerji API Sunucusu Başlatılıyor...")
    app.run(debug=True, port=5000)
