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
        email = request.form.get('email')
        password = request.form.get('password').encode('utf-8')
        cursor.execute("SELECT email, password, is_verified, role FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
            if user[2]:  # Check is_verified
                session['email'] = email
                session['role'] = user[3]  # Store role in session
                return redirect(url_for('dashboard'))  # Redirect to dashboard
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
        password = request.form.get('password').encode('utf-8')
        role = request.form.get('role')

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        verification_token = str(uuid.uuid4())

        try:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, role, verification_token, is_verified) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (first_name, last_name, email, hashed_pw.decode('utf-8'), role, verification_token, False)
            )
            conn.commit()
            send_verification_email(email, verification_token)
            flash("Registration successful! Please check your email to verify your account.")
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Email already exists.")
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
    session.pop('email', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT user_id, first_name, last_name, email, role FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    user_id, first_name, last_name, email, role = user

    # Tutor: Create classroom and invite students
    if role == 'tutor':
        # Get tutor's students
        cursor.execute("SELECT u.user_id, u.first_name, u.last_name, u.email "
                      "FROM users u JOIN tutor_student ts ON u.user_id = ts.student_id "
                      "WHERE ts.tutor_id = %s", (user_id,))
        students = cursor.fetchall()

        # Get tutor's classrooms (distinct room names)
        cursor.execute("SELECT DISTINCT room_name FROM invitations WHERE tutor_id = %s", (user_id,))
        classrooms = [row[0] for row in cursor.fetchall()]

        if request.method == 'POST':
            if 'create_room' in request.form:
                room_name = request.form.get('room_name')
                student_ids = request.form.getlist('students')  # Multiple students can be invited
                for student_id in student_ids:
                    cursor.execute(
                        "INSERT INTO invitations (tutor_id, student_id, room_name) VALUES (%s, %s, %s)",
                        (user_id, student_id, room_name)
                    )
                conn.commit()
                flash(f"Classroom '{room_name}' created and students invited.")
                return redirect(url_for('dashboard'))

    # Student: See invited classrooms
    else:
        cursor.execute("SELECT room_name FROM invitations WHERE student_id = %s", (user_id,))
        classrooms = [row[0] for row in cursor.fetchall()]

    return render_template('dashboard.html', role=role, first_name=first_name, last_name=last_name, email=email, classrooms=classrooms, students=students if role == 'tutor' else None)

@app.route('/classroom/<room_name>')
def classroom(room_name):
    if 'email' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT user_id, role FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    user_id, role = user

    # Check if user has access to the room
    if role == 'tutor':
        cursor.execute("SELECT 1 FROM invitations WHERE tutor_id = %s AND room_name = %s", (user_id, room_name))
    else:
        cursor.execute("SELECT 1 FROM invitations WHERE student_id = %s AND room_name = %s", (user_id, room_name))
    
    if not cursor.fetchone():
        flash("You don’t have access to this room.")
        return redirect(url_for('dashboard'))

    return render_template('classroom.html', roomName=room_name)

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password').encode('utf-8')
        new_password = request.form.get('new_password').encode('utf-8')

        cursor.execute("SELECT password FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(current_password, user[0].encode('utf-8')):
            hashed_new_pw = bcrypt.hashpw(new_password, bcrypt.gensalt())
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_new_pw.decode('utf-8'), session['email']))
            conn.commit()
            flash("Password updated successfully.")
        else:
            flash("Current password is incorrect.")
        return redirect(url_for('dashboard'))

    return render_template('update_password.html')

@app.route('/update_info', methods=['GET', 'POST'])
def update_info():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        cursor.execute("UPDATE users SET first_name = %s, last_name = %s WHERE email = %s", (first_name, last_name, session['email']))
        conn.commit()
        flash("Personal information updated successfully.")
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT first_name, last_name FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    return render_template('update_info.html', first_name=user[0], last_name=user[1])

@app.route('/assign_student', methods=['POST'])
def assign_student():
    if 'email' not in session or session['role'] != 'tutor':
        return redirect(url_for('login'))

    cursor.execute("SELECT user_id FROM users WHERE email = %s", (session['email'],))
    tutor_id = cursor.fetchone()[0]

    student_email = request.form.get('student_email')
    cursor.execute("SELECT user_id FROM users WHERE email = %s AND role = 'student'", (student_email,))
    student = cursor.fetchone()

    if student:
        try:
            cursor.execute("INSERT INTO tutor_student (tutor_id, student_id) VALUES (%s, %s)", (tutor_id, student[0]))
            conn.commit()
            flash(f"Student {student_email} assigned successfully.")
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Student is already assigned to you.")
    else:
        flash("Student not found.")
    return redirect(url_for('dashboard'))

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