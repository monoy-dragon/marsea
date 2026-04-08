from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import bcrypt
import sqlite3

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
            conn.close()
            return jsonify({"message": "Email sudah terdaftar"}), 400

        # 🔥 HASH PASSWORD (STRING CONSISTENT)
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        cur.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed, "user")
        )

        conn.commit()
        user_id = cur.lastrowid

        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        conn.close()

        token = jwt.encode({
            "user_id": user["id"],
            "role": user["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "message": "Register berhasil",
            "token": token,
            "user": dict(user)
        })

    except Exception as e:
        print("🔥 REGISTER ERROR:", e)
        return jsonify({"message": "Server error"}), 500


# ================= LOGIN =================
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
        conn.close()

        if not user:
            return jsonify({"message": "User tidak ditemukan"}), 401

        stored_password = user["password"]

        # 🔥 FIX BCRYPT (STRING → BYTES)
        if isinstance(stored_password, str):
            stored_password = stored_password.encode()

        if not bcrypt.checkpw(password.encode(), stored_password):
            return jsonify({"message": "Password salah"}), 401

        token = jwt.encode({
            "user_id": user["id"],
            "role": user["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "message": "Login berhasil",
            "token": token,
            "user": dict(user)
        })

    except Exception as e:
        print("🔥 LOGIN ERROR:", e)
        return jsonify({"message": "Server error"}), 500


# ================= ME =================
@app.route("/api/auth/me", methods=["GET"])
def me():
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id = ?", (user["user_id"],))
    db_user = cur.fetchone()
    conn.close()

    return jsonify(dict(db_user))


# ================= CREATE BOOKING =================
@app.route("/api/bookings", methods=["POST"])
def create_booking():
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    try:
        data = request.get_json()

        service_name = data.get("service_name")
        vessel_class = data.get("vessel_class")
        mode = data.get("mode")

        if not service_name or not vessel_class or not mode:
            return jsonify({"message": "Data tidak lengkap"}), 400

        qty = int(data.get("qty", 1))
        total_price = int(data.get("total_price", 0))

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO bookings 
            (user_id, service_name, vessel_class, mode, qty, total_price, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user["user_id"],
            service_name,
            vessel_class,
            mode,
            qty,
            total_price,
            "pending"
        ))

        conn.commit()
        conn.close()

        return jsonify({"message": "Booking berhasil", "status": "pending"})

    except Exception as e:
        print("❌ ERROR CREATE BOOKING:", e)
        return jsonify({"message": "Server error"}), 500


# ================= USER BOOKINGS =================
@app.route("/api/bookings", methods=["GET"])
def get_bookings():
    user = get_current_user()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM bookings 
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user["user_id"],))

    rows = cur.fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


# ================= ADMIN: GET BOOKINGS =================
@app.route("/api/admin/bookings", methods=["GET"])
def admin_bookings():
    user = get_current_user()

    if not user or user["role"] != "admin":
        return jsonify({"message": "Forbidden"}), 403

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM bookings ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


# ================= ADMIN: UPDATE STATUS =================
@app.route("/api/admin/bookings/<int:id>/status", methods=["PUT"])
def update_status(id):
    user = get_current_user()

    if not user or user["role"] != "admin":
        return jsonify({"message": "Forbidden"}), 403

    data = request.get_json()
    status = data.get("status")

    if status not in ["pending", "approved", "rejected"]:
        return jsonify({"message": "Status tidak valid"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM bookings WHERE id = ?", (id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"message": "Booking tidak ditemukan"}), 404

    cur.execute(
        "UPDATE bookings SET status = ? WHERE id = ?",
        (status, id)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "Status updated", "status": status})


# ================= ROOT =================
@app.route("/")
def home():
    return "MARSEA API is running 🚀"


# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    app.run()