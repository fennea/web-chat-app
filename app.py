from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import psycopg2
import bcrypt
import smtplib
from email.mime.text import MIMEText
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
import stripe
import requests
import logging

load_dotenv()

# Set up logging to print errors to the console and file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s',
    handlers=[
        logging.FileHandler('twotoro.log'),
        logging.StreamHandler()  # This adds console output
    ]
)

# Log dependency versions
logging.info(f"Stripe version: {stripe._version}")
logging.info(f"Requests version: {requests.__version__}")
logging.info(f"Urllib3 version: {urllib3.__version__}")

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection
DB_URL = os.environ.get('DATABASE_URL', 'postgres://anthonyfenner@localhost:5432/chitchat_db')
conn = None
cursor = None
db_connected = False

try:
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT 1")  # Test the connection
    db_connected = True
    logging.info("Database connection established successfully")
except Exception as e:
    logging.error(f"Failed to establish database connection: {str(e)}", exc_info=True)
    # Do not raise an exception here; allow the app to start

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')

# Stripe Product and Price IDs (set these in Stripe Dashboard)
FREE_PLAN = 'free'
LIFETIME_FREE_PLAN = 'lifetime_free'
EARLY_ADOPTER_PRICE_ID = 'price_1...'  # Replace with your Early Adopter Price ID
STANDARD_PRICE_ID = 'price_1...'      # Replace with your Standard Price ID

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

def get_user_session_count(user_id, month_start, month_end):
    cursor.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s AND start_time BETWEEN %s AND %s",
        (user_id, month_start, month_end)
    )
    return cursor.fetchone()[0]

def get_user_subscription(user_id):
    cursor.execute("SELECT lifetime_free FROM users WHERE user_id = %s", (user_id,))
    lifetime_free = cursor.fetchone()[0]
    if lifetime_free:
        return LIFETIME_FREE_PLAN, 'active'
    cursor.execute("SELECT plan, status FROM subscriptions WHERE user_id = %s", (user_id,))
    sub = cursor.fetchone()
    return sub if sub else (FREE_PLAN, 'active')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password').encode('utf-8')
        cursor.execute("SELECT email, password, is_verified, role FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
            if user[2]:
                session['email'] = email
                session['role'] = user[3]
                return redirect(url_for('dashboard'))
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
        lifetime_free = request.form.get('lifetime_free') == 'true'
        plan = request.form.get('plan')  # Get selected plan

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        verification_token = str(uuid.uuid4())

        try:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, role, verification_token, is_verified, early_adopter, lifetime_free) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING user_id",
                (first_name, last_name, email, hashed_pw.decode('utf-8'), role, verification_token, False, plan == 'early_adopter', lifetime_free)
            )
            user_id = cursor.fetchone()[0]
            if plan == 'early_adopter':
                return redirect(url_for('register_complete', user_id=user_id, email=email))
            else:
                cursor.execute(
                    "INSERT INTO subscriptions (user_id, stripe_subscription_id, plan, status) VALUES (%s, %s, %s, %s)",
                    (user_id, '', FREE_PLAN if not lifetime_free else LIFETIME_FREE_PLAN, 'active')
                )
                conn.commit()
                send_verification_email(email, verification_token)
                flash("Registration successful! Please check your email to verify your account.")
                return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Email already exists.")
    return render_template('register.html')

@app.route('/register_complete/<user_id>/<email>', methods=['GET', 'POST'])
def register_complete(user_id, email):
    if request.method == 'POST':
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': EARLY_ADOPTER_PRICE_ID,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url='https://twotoro.com/verify_subscription?user_id={}&session_id={{CHECKOUT_SESSION_ID}}'.format(user_id),
                cancel_url='https://twotoro.com/register?cancel=true',
                customer_email=email,
                payment_method_collection='if_required',
                payment_intent_data={
                    'statement_descriptor': 'TwoToro EarlyAdopter'
                }
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            flash(f"Error creating checkout session: {str(e)}")
            return redirect(url_for('register'))
    return render_template('register_complete.html', user_id=user_id, email=email, stripe_publishable_key=STRIPE_PUBLISHABLE_KEY)

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

    if role == 'tutor':
        cursor.execute("SELECT u.user_id, u.first_name, u.last_name, u.email "
                      "FROM users u JOIN tutor_student ts ON u.user_id = ts.student_id "
                      "WHERE ts.tutor_id = %s", (user_id,))
        students = cursor.fetchall()
        cursor.execute("SELECT DISTINCT room_name FROM invitations WHERE tutor_id = %s", (user_id,))
        classrooms = [row[0] for row in cursor.fetchall()]

        if request.method == 'POST':
            if 'create_room' in request.form:
                room_name = request.form.get('room_name')
                student_ids = request.form.getlist('students')
                for student_id in student_ids:
                    cursor.execute(
                        "INSERT INTO invitations (tutor_id, student_id, room_name) VALUES (%s, %s, %s)",
                        (user_id, student_id, room_name)
                    )
                conn.commit()
                flash(f"Classroom '{room_name}' created and students invited.")
                return redirect(url_for('dashboard'))

    else:
        cursor.execute("SELECT room_name FROM invitations WHERE student_id = %s", (user_id,))
        classrooms = [row[0] for row in cursor.fetchall()]
        students = None

    return render_template('dashboard.html', role=role, first_name=first_name, last_name=last_name, email=email, classrooms=classrooms, students=students)

@app.route('/classroom/<room_name>')
def classroom(room_name):
    if 'email' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT user_id, role, lifetime_free FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    user_id, role, lifetime_free = user

    # Check session limits (exempt lifetime free and paid users)
    if not lifetime_free:
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        session_count = get_user_session_count(user_id, month_start, month_end)
        plan, status = get_user_subscription(user_id)

        if plan == FREE_PLAN and session_count >= 4:
            flash("You’ve reached your free session limit (4 sessions/month). Please upgrade to continue.")
            return redirect(url_for('upgrade'))
    else:
        plan, status = get_user_subscription(user_id)

    # Check if user has access to the room
    if role == 'tutor':
        cursor.execute("SELECT 1 FROM invitations WHERE tutor_id = %s AND room_name = %s", (user_id, room_name))
    else:
        cursor.execute("SELECT 1 FROM invitations WHERE student_id = %s AND room_name = %s", (user_id, room_name))
    
    if not cursor.fetchone():
        flash("You don’t have access to this room.")
        return redirect(url_for('dashboard'))

    # Start session tracking
    cursor.execute(
        "INSERT INTO sessions (user_id, start_time) VALUES (%s, %s) RETURNING session_id",
        (user_id, datetime.utcnow())
    )
    session['current_session_id'] = cursor.fetchone()[0]
    conn.commit()

    return render_template('classroom.html', roomName=room_name, userPlan=plan)

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

@app.route('/upgrade', methods=['GET', 'POST'])
def upgrade():
    if 'email' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT user_id, early_adopter, lifetime_free FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    user_id, early_adopter, lifetime_free = user

    if lifetime_free:
        flash("You already have a lifetime free subscription with all benefits!")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        price_id = EARLY_ADOPTER_PRICE_ID if early_adopter else STANDARD_PRICE_ID
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url='https://twotoro.com/dashboard?success=true',
                cancel_url='https://twotoro.com/upgrade?cancel=true',
                customer_email=session['email'],
                payment_method_collection='if_required',
                payment_intent_data={
                    'statement_descriptor': 'TwoToro EarlyAdopter' if early_adopter else 'TwoToro Standard'
                }
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            flash(f"Error creating checkout session: {str(e)}")
            return redirect(url_for('upgrade'))

    return render_template('upgrade.html', stripe_publishable_key=STRIPE_PUBLISHABLE_KEY)

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

@socketio.on('session_update')
def on_session_update(data):
    if 'email' not in session or 'current_session_id' not in session:
        return

    duration = data.get('duration', 0)
    cursor.execute(
        "UPDATE sessions SET duration = %s WHERE session_id = %s",
        (duration, session['current_session_id'])
    )
    conn.commit()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)

def shutdown():
    cursor.close()
    conn.close()
import atexit
atexit.register(shutdown)