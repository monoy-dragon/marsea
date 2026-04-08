from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import bcrypt
import sqlite3
import json
import os

app = Flask(__name__)

# ================= CORS =================
CORS(app, resources={r"/*": {"origins": "*"}})

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({"message": "OK"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        return response

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response

SECRET_KEY = "marsea_secret_key"

# ================= DATABASE =================
def get_db():
    conn = sqlite3.connect("marsea.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        service_name TEXT,
        vessel_class TEXT,
        mode TEXT,
        qty INTEGER,
        total_price INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= AUTH =================
def get_current_user():
    auth = request.headers.get("Authorization")

    if not auth:
        return None

    try:
        token = auth.split(" ")[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except Exception as e:
        print("❌ AUTH ERROR:", e)
        return None

# ================= REGISTER =================
@app.route("/api/auth/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"message": "No data"}), 400

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"message": "Semua field wajib"}), 400

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            return jsonify({"message": "Email sudah terdaftar"}), 400

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        cur.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed, "user")
        )

        conn.commit()
        user_id = cur.lastrowid

        token = jwt.encode({
            "user_id": user_id,
            "role": "user",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, SECRET_KEY, algorithm="HS256")

        conn.close()

        return jsonify({
            "message": "Register berhasil",
            "token": token
        })

    except Exception as e:
        print("🔥 REGISTER ERROR:", e)
        return jsonify({"message": "Server error"}), 500


# ================= LOGIN (FIX UTAMA) =================
@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"message": "No data"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"message": "Email & password wajib"}), 400

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({"message": "User tidak ditemukan"}), 401

        stored_password = user["password"]

        if isinstance(stored_password, str):
            stored_password = stored_password.encode()

        if not bcrypt.checkpw(password.encode(), stored_password):
            return jsonify({"message": "Password salah"}), 401

        token = jwt.encode({
            "user_id": user["id"],
            "role": user["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, SECRET_KEY, algorithm="HS256")

        conn.close()

        # 🔥 FIX: kirim user ke frontend
        return jsonify({
            "message": "Login berhasil",
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
        })

    except Exception as e:
        print("🔥 LOGIN ERROR:", e)
        return jsonify({"message": "Server error"}), 500


# ================= GET SERVICES =================
@app.route("/prices", methods=["GET"])
def get_prices():
    try:
        file_path = os.path.join(os.getcwd(), "prices.json")

        if not os.path.exists(file_path):
            return jsonify({"message": "prices.json tidak ditemukan"}), 404

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return jsonify(data)

    except Exception as e:
        print("❌ ERROR LOAD PRICES:", e)
        return jsonify({"message": "Gagal load data services"}), 500


# ================= BOOKING =================
@app.route("/api/bookings", methods=["POST"])
def create_booking():
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    try:
        data = request.get_json()

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO bookings 
            (user_id, service_name, vessel_class, mode, qty, total_price)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user["user_id"],
            data.get("service_name"),
            data.get("vessel_class"),
            data.get("mode"),
            int(data.get("qty", 1)),
            int(data.get("total_price", 0))
        ))

        conn.commit()
        conn.close()

        return jsonify({"message": "Booking berhasil"})

    except Exception as e:
        print("❌ BOOKING ERROR:", e)
        return jsonify({"message": "Server error"}), 500


# ================= HEALTH =================
@app.route("/health")
def health():
    return jsonify({"status": "OK"})


# ================= ROOT =================
@app.route("/")
def home():
    return "MARSEA API is running 🚀"


# ================= RUN =================
PORT = int(os.environ.get("PORT", 5000))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
