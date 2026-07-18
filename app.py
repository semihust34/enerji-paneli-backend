from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# CORS'u daha geniş ve kesin tanımlayalım
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Preflight (OPTIONS) isteklerini manuel olarak karşılayalım
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,ngrok-skip-browser-warning")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        return response, 200

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
        cursor.execute("SELECT id, role FROM users WHERE username = %s AND plain_password = %s;", (username, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            return jsonify({"success": True, "role": user[1], "token": "gercek_sistem_tokeni"}), 200
        else:
            return jsonify({"success": False, "message": "Kullanıcı adı veya şifre hatalı!"}), 401
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/customers', methods=['POST'])
def add_customer():
    try:
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
def delete_customer(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
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
def update_customer(user_id):
    try:
        data = request.json
        factories = data.get('factories', '') # Güncellenen fabrikaları al

        conn = get_db_connection()
        cursor = conn.cursor()
        
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
            
        cursor.close()
        conn.close()
        return jsonify({"success": True, "factories": factory_list}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/factories/<int:factory_id>', methods=['DELETE'])
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
