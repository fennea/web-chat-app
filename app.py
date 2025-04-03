from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import psycopg2
import bcrypt
import smtplib
from email.mime.text import MIMEText
import uuid
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

DB_URL = os.environ.get('DATABASE_URL', 'postgres://anthonyfenner@localhost:5432/chitchat_db')
conn = psycopg2.connect(DB_URL)
cursor = conn.cursor()

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def send_verification_email(email, token):
    msg = MIMEText(f"Please verify your email by clicking this link: https://twotoro.com/verify/{token}")
    msg['Subject'] = 'TwoToro Email Verification'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Changed from username
        password = request.form.get('password').encode('utf-8')
        cursor.execute("SELECT email, password, is_verified FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
            if user[2]:  # Check is_verified
                session['email'] = email  # Store email in session instead of username
                return redirect(url_for('select_classroom'))
            else:
                flash("Please verify your email before logging in.")
        else:
            flash("Invalid email or password. Please try again.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        username = request.form.get('username')  # Still collected but not used for login
        password = request.form.get('password').encode('utf-8')
        role = request.form.get('role')

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        verification_token = str(uuid.uuid4())

        try:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, username, password, role, verification_token, is_verified) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (first_name, last_name, email, username, hashed_pw.decode('utf-8'), role, verification_token, False)
            )
            conn.commit()
            send_verification_email(email, verification_token)
            flash("Registration successful! Please check your email to verify your account.")
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Username or email already exists.")
    return render_template('register.html')

@app.route('/verify/<token>')
def verify(token):
    cursor.execute("SELECT email FROM users WHERE verification_token = %s AND is_verified = FALSE", (token,))
    user = cursor.fetchone()
    if user:
        cursor.execute("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = %s", (token,))
        conn.commit()
        flash("Email verified! You can now log in.")
    else:
        flash("Invalid or expired verification link.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('email', None)  # Changed from 'username'
    return redirect(url_for('login'))

@app.route('/select_classroom', methods=['GET', 'POST'])
def select_classroom():
    if 'email' not in session:  # Changed from 'username'
        return redirect(url_for('login'))
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        return redirect(url_for('classroom', room_name=room_name))
    return render_template('select_classroom.html')

@app.route('/classroom/<room_name>')
def classroom(room_name):
    if 'email' not in session:  # Changed from 'username'
        return redirect(url_for('login'))
    return render_template('classroom.html', roomName=room_name)

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        print(f"User joined room: {room}")
        emit('user-joined', {'msg': 'A new user has joined the room!'}, room=room)

@socketio.on('signal')
def handle_signal(data):
    room = data.get('room')
    if room:
        emit('signal', data, room=room, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)

def shutdown():
    cursor.close()
    conn.close()
import atexit
atexit.register(shutdown)