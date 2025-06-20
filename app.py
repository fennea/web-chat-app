import gevent.monkey
gevent.monkey.patch_all()

from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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
import urllib3
import time
import pytz
import uuid
import re

load_dotenv()

# Set up logging to print errors to the console and file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s',
    handlers=[
        logging.FileHandler('twotoro.log'),
        logging.StreamHandler()  # This adds console output
    ],
    force=True  # Ensure logging configuration is applied
)

# Log dependency versions
logging.info(f"Stripe version: {stripe.VERSION}")  # Fixed: Use stripe.__version__
logging.info(f"Requests version: {requests.__version__}")
logging.info(f"Urllib3 version: {urllib3.__version__}")

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode='gevent')

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL')
DB_URL = os.environ.get('DATABASE_URL', DATABASE_URL)
conn = None
cursor = None
db_connected = False

user_counts = defaultdict(int)
user_room_map = {}

# Set global timezone in app config
app.config['TIMEZONE'] = 'UTC'

# Optional: Define a helper to get the timezone
def get_app_timezone():
    return pytz.timezone(app.config['TIMEZONE'])

try:
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT 1")  # Test the connection
    db_connected = True
    logging.info("Database connection established successfully")
except Exception as e:
    logging.error(f"Failed to establish database connection: {str(e)}", exc_info=True)

def check_db_connection():
    global conn, cursor, db_connected
    if not db_connected:
        return False, "The application is currently unable to connect to the database. Please try again later."
    start_time = time.time()
    while time.time() - start_time < 10:    
        try:
            cursor.execute("SELECT 1")
            return True, None
        except Exception as e:
            logging.error(f"Database connection check failed: {str(e)}", exc_info=True)
            # Attempt to reconnect
            try:
                conn = psycopg2.connect(DB_URL)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                db_connected = True
                logging.info("Database connection re-established successfully")
                return True, None
            except Exception as reconnect_error:
                logging.error(f"Failed to reconnect to database: {str(reconnect_error)}", exc_info=True)
                db_connected = False
                return False, "The application is currently unable to connect to the database. Please try again later."
        time.sleep(1)


def generate_room_slug(room_name):
    # Remove unwanted characters and convert spaces to dashes
    base = re.sub(r'\W+', '-', room_name.lower())
    # Append a short token, e.g., part of a UUID
    token = str(uuid.uuid4())[:8]
    return f"{base}-{token}"

def add_user_to_room(user_id, room):
    if user_id not in user_room_map:
        user_room_map[user_id] = set()
    user_room_map[user_id].add(room)

def get_user_rooms(user_id):
    return user_room_map.get(user_id, set())

# Add a before_request hook to log all incoming requests
@app.before_request
def log_request():
    try:
        logging.info(f"Incoming request: {request.method} {request.url}")
    except Exception as e:
        logging.error(f"Error in before_request: {str(e)}", exc_info=True)
        raise

# Add an error handler to catch unhandled exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
    flash("An unexpected error occurred. Please try again later.")
    return redirect(url_for('login'))

@app.route('/test')
def test():
    logging.info("Test route accessed")
    return "Test route is working!"

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')

# Constants for subscription plans
FREE_PLAN = 'free'
LIFETIME_FREE_PLAN = 'lifetime_free'
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

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
        logging.info(f"Verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send email to {email}: {str(e)}")
        raise e

@app.route('/request_link', methods=['POST'])
def request_link():
    if 'email' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    parent_email = session['email']
    student_email = request.form.get('student_email')  # 👈 now get from form, not JSON

    cursor.execute("SELECT user_id FROM users WHERE email = %s", (student_email,))
    student = cursor.fetchone()

    if student:
        student_id = student[0]
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (parent_email,))
        parent_id = cursor.fetchone()[0]

        # Insert pending link
        cursor.execute("""
            INSERT INTO parent_student_requests (parent_id, student_id, status, requested_at)
            VALUES (%s, %s, 'pending', NOW())
        """, (parent_id, student_id))
        conn.commit()

    flash("If this student is a member of Twotoro, they will receive your request.")
    return redirect(url_for('dashboard'))


def get_user_session_count(user_id, month_start, month_end):
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for get_user_session_count: {db_error}")
        raise Exception(db_error)

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s AND start_time BETWEEN %s AND %s",
            (user_id, month_start, month_end)
        )
        return cursor.fetchone()[0]
    except Exception as e:
        logging.error(f"Error getting session count for user_id {user_id}: {str(e)}", exc_info=True)
        raise

def get_user_subscription(user_id):
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for get_user_subscription: {db_error}")
        raise Exception(db_error)

    try:
        cursor.execute("SELECT lifetime_free FROM users WHERE user_id = %s", (user_id,))
        lifetime_free = cursor.fetchone()[0]
        if lifetime_free:
            return LIFETIME_FREE_PLAN, 'active'
        cursor.execute("SELECT plan, status FROM subscriptions WHERE user_id = %s", (user_id,))
        sub = cursor.fetchone()
        return sub if sub else (FREE_PLAN, 'active')
    except Exception as e:
        logging.error(f"Error getting subscription for user_id {user_id}: {str(e)}", exc_info=True)
        raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for login: {db_error}")
        flash(db_error)
        return render_template('login.html')

    try:
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password').encode('utf-8')
            cursor.execute("SELECT user_id, email, password, is_verified, role FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(password, user[2].encode('utf-8')):
                if user[3]:
                    session['user_id'] = user[0]
                    session['email'] = email
                    session['role'] = user[4]
                    logging.info(f"Successful login for email: {email}, role: {user[4]}")
                    if user[4] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    return redirect(url_for('dashboard'))
                else:
                    flash("Please verify your email before logging in.")
                    logging.warning(f"Login failed for email: {email} - Email not verified")
            else:
                flash("Invalid email or password. Please try again.")
                logging.warning(f"Failed login attempt for email: {email}")
        return render_template('login.html')
    except Exception as e:
        logging.error(f"Error in login for email {email}: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}")
        return render_template('login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'email' not in session or session['role'] != 'admin':
        flash("You must be an admin to access this page.")
        logging.warning(f"Unauthorized access to admin_dashboard: email={session.get('email', 'None')}, role={session.get('role', 'None')}")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for admin_dashboard: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        # Fetch user stats
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM subscriptions WHERE plan != %s AND plan != %s", (FREE_PLAN, LIFETIME_FREE_PLAN))
        paid_users = cursor.fetchone()[0]
        free_users = total_users - paid_users
        logging.info(f"Total users: {total_users}, Paid users: {paid_users}, Free users: {free_users}")

        # Fetch active sessions
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE start_time >= NOW() - INTERVAL '30 minutes'")
        active_sessions = cursor.fetchone()[0]
        logging.info(f"Active sessions: {active_sessions}")

        # Fetch products
        cursor.execute("SELECT product_id, name, price, description, stripe_price_id, active FROM products")
        products = cursor.fetchall()
        logging.info(f"Products fetched: {len(products)}")

        if request.method == 'POST':
            if 'add_product' in request.form:
                name = request.form.get('name')
                price = request.form.get('price')
                description = request.form.get('description')
                stripe_price_id = request.form.get('stripe_price_id')
                active = request.form.get('active') == 'on'

                # Validate price
                try:
                    price = float(price) if price else 0.0
                except (ValueError, TypeError):
                    flash("Price must be a valid number.")
                    return redirect(url_for('admin_dashboard'))

                try:
                    cursor.execute(
                        "INSERT INTO products (name, price, description, stripe_price_id, active) VALUES (%s, %s, %s, %s, %s)",
                        (name, price, description, stripe_price_id, active)
                    )
                    conn.commit()
                    flash("Product added successfully.")
                    logging.info(f"Admin added product: {name}")
                except Exception as e:
                    conn.rollback()
                    flash(f"Error adding product: {str(e)}")
                    logging.error(f"Admin failed to add product: {str(e)}", exc_info=True)

            elif 'update_product' in request.form:
                product_id = request.form.get('product_id')
                name = request.form.get('name')
                price = request.form.get('price')
                description = request.form.get('description')
                stripe_price_id = request.form.get('stripe_price_id')
                active = request.form.get('active') == 'on'

                # Validate price
                try:
                    price = float(price) if price else 0.0
                except (ValueError, TypeError):
                    flash("Price must be a valid number.")
                    return redirect(url_for('admin_dashboard'))

                try:
                    cursor.execute(
                        "UPDATE products SET name = %s, price = %s, description = %s, stripe_price_id = %s, active = %s WHERE product_id = %s",
                        (name, price, description, stripe_price_id, active, product_id)
                    )
                    conn.commit()
                    flash("Product updated successfully.")
                    logging.info(f"Admin updated product ID {product_id}: {name}")
                except Exception as e:
                    conn.rollback()
                    flash(f"Error updating product: {str(e)}")
                    logging.error(f"Admin failed to update product ID {product_id}: {str(e)}", exc_info=True)

            return redirect(url_for('admin_dashboard'))

        return render_template('admin_dashboard.html', total_users=total_users, paid_users=paid_users, free_users=free_users, active_sessions=active_sessions, products=products)

    except Exception as e:
        logging.error(f"Admin dashboard error: {str(e)}", exc_info=True)
        flash(f"An error occurred while loading the admin dashboard: {str(e)}")
        return redirect(url_for('login'))

@app.route('/tutor_signup', methods=['GET', 'POST'])
def tutor_signup():
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for tutor_signup: {db_error}")
        flash(db_error)
        return redirect(url_for('register'))
    
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()

    # First, try to get the email from query parameters or from the form submission
    email = request.args.get('email') or request.form.get('email')

    try:
        # Get the current user based on the provided email
        cursor.execute(
            "SELECT user_id, first_name, last_name, email, role FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()
        logging.info(f"User fetched for tutor_signup with email {email}: {user}")

        if not user:
            flash("Error: User not found")
            return redirect(url_for('register'))

        user_id = user[0]

        if request.method == 'POST':
            # Retrieve the selected plan from the form
            selected_plan = request.form.get('selected_plan')
            logging.info(f"Selected plan (type: {type(selected_plan)}): {selected_plan}")
            logging.info(f"Selected plan for user_id {user_id}: {selected_plan}")
            if not selected_plan:
                flash("Please select a plan before proceeding.")
                return redirect(url_for('tutor_signup', email=email))

            # Retrieve the product from the database using a parameterized query
            cursor.execute(
                "SELECT product_id, name, price, description, stripe_price_id, active FROM products WHERE product_id = %s ORDER BY price",
                (selected_plan,)
            )
            product = cursor.fetchone()

            if selected_plan == '1' or selected_plan == '2':

                # Update the subscriptions table
                cursor.execute(
                    "INSERT INTO subscriptions (user_id, plan, status) VALUES (%s, %s, %s)",
                    (user_id, selected_plan, 'active',)
                )
                conn.commit()

                if selected_plan == '1':
                    cursor.execute("UPDATE users SET lifetime_free = true WHERE user_id = %s", (user_id,))
                    conn.commit()
                    flash("Registration successful! Please check your email to verify your account.")
                    return redirect(url_for('login'))

                if selected_plan == '2':
                    flash("Registration successful! Please check your email to verify your account.")
                    return redirect(url_for('login'))

            logging.info(f"Product fetched for selected_plan {selected_plan}: {product}")
            if not product:
                flash("Error: Selected plan not found")
                return redirect(url_for('tutor_signup', email=email))

            # The stripe_price_id is in column index 4
            stripe_price_id = product[4]
            product_name = product[1]

            # Build a dynamic statement descriptor
            descriptor = f"TwoToro {product_name}"
            max_length = 22
            if len(descriptor) > max_length:
                descriptor = descriptor[:max_length].rstrip()

            try:
                # Create a Stripe checkout session in subscription mode
                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price': stripe_price_id,  # dynamically from the product record
                        'quantity': 1,
                    }],
                    mode='subscription',
                    success_url=f'https://twotoro.com/verify_subscription?user_id={user_id}&session_id={{CHECKOUT_SESSION_ID}}&selected_plan={selected_plan}',
                    cancel_url='https://twotoro.com/register?cancel=true',
                    customer_email=email,
                    payment_method_collection='if_required'
                )
                logging.info(f"Checkout session created for user_id {user_id}: {checkout_session.id}")
                return redirect(checkout_session.url, code=303)
            except Exception as e:
                logging.error(f"Error creating checkout session for user_id {user_id}: {str(e)}", exc_info=True)
                flash(f"Error creating checkout session: {str(e)}")
                return redirect(url_for('register'))
        else:
            # GET: Fetch active products to populate the drop-down
            cursor.execute(
                "SELECT product_id, name, price, description, stripe_price_id, active FROM products WHERE active = TRUE"
            )
            products = cursor.fetchall()
            logging.info(f"Products fetched for tutor_signup: {products}")
            return render_template('tutor_signup.html', user=user, products=products)

    except Exception as e:
        logging.error(f"Error in tutor_signup for email {email}: {str(e)}", exc_info=True)
        flash(f"Error loading tutor signup page: {str(e)}")
        return redirect(url_for('register'))

@app.route('/verify_subscription', methods=['GET'])
def verify_subscription():
    user_id = request.args.get('user_id')
    session_id = request.args.get('session_id')
    selected_plan = request.args.get('selected_plan')

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for verify_subscription: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        # Retrieve the Checkout session from Stripe
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        subscription_id = checkout_session.subscription
        logging.info(f"Checkout session retrieved for user_id {user_id}: {checkout_session.id}, subscription_id: {subscription_id}")

        # Update the subscriptions table
        cursor.execute(
            "INSERT INTO subscriptions (user_id, stripe_subscription_id, plan, status) VALUES (%s, %s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET stripe_subscription_id = %s, plan = %s, status = %s",
            (user_id, subscription_id, selected_plan, 'active', subscription_id, selected_plan, 'active')
        )
        conn.commit()
        logging.info(f"Subscription updated for user_id {user_id}: subscription_id {subscription_id}")
        flash("Payment successful! Your subscription is now active.")
    except Exception as e:
        logging.error(f"Error verifying subscription for user_id {user_id}: {str(e)}", exc_info=True)
        flash(f"Error verifying subscription: {str(e)}")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for register: {db_error}")
        flash(db_error)
        return render_template('register.html')

    try:
        if request.method == 'POST':
            conn = psycopg2.connect(DB_URL)
            cursor = conn.cursor()

            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            password = request.form.get('password').encode('utf-8')
            role = request.form.get('role')
            # lifetime_free = request.form.get('lifetime_free') == 'true'
            # plan = request.form.get('plan')  # Get selected plan
            logging.info(f"Register attempt for email {email}, role: {role}, lifetime_free: False")

            # Validate role
            if role not in ['tutor', 'student', 'parent']:
                flash("Invalid role selected.")
                logging.error(f"Invalid role selected during registration: {role}")
                return redirect(url_for('register'))

            hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
            verification_token = str(uuid.uuid4())

            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, role, verification_token, is_verified, lifetime_free) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING user_id",
                (first_name, last_name, email, hashed_pw.decode('utf-8'), role, verification_token, False, False,)
            )
            user_id = cursor.fetchone()[0]
            conn.commit()
            logging.info(f"User created with user_id:: {user_id}")

            if role == 'tutor':
                send_verification_email(email, verification_token)
                return redirect(url_for('tutor_signup', email=email))
            else:
                send_verification_email(email, verification_token)
                flash("Registration successful! Please check your email to verify your account.")
                return redirect(url_for('login'))
        else:
            return render_template('register.html')

    except psycopg2.IntegrityError:
        conn.rollback()
        flash("Email already exists.")
        logging.error(f"Registration failed: Email {email} already exists")
        return render_template('register.html')
    except Exception as e:
        conn.rollback()
        logging.error(f"Error in register for email {email}: {str(e)}", exc_info=True)
        flash(f"Error during registration: {str(e)}")
        return render_template('register.html')

# Updated /verify/<token> route
@app.route('/verify/<token>')
def verify(token):
    logging.info(f"Attempting to verify token: {token}")
    
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for token verification: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        cursor.execute("SELECT email FROM users WHERE verification_token = %s AND is_verified = FALSE", (token,))
        user = cursor.fetchone()
        logging.info(f"User fetched for token {token}: {user}")
        if user:
            cursor.execute("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = %s", (token,))
            conn.commit()
            flash("Email verified! You can now log in.")
            logging.info(f"Email verified for token: {token}")
        else:
            flash("Invalid or expired verification link.")
            logging.warning(f"Invalid verification token: {token}")
    except Exception as e:
        logging.error(f"Error verifying token {token}: {str(e)}", exc_info=True)
        flash("An error occurred during email verification. Please try again.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    session.pop('role', None)
    logging.info(f"User logged out: {session.get('email', 'unknown')}")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for dashboard: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        cursor.execute("SELECT user_id, first_name, last_name, email, role FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        if not user:
            flash("User not found.")
            logging.warning(f"User not found for email: {session['email']}")
            return redirect(url_for('login'))

        user_id, first_name, last_name, email, role = user
        
        pending_parent_requests = []  # Always define early

        # ✅ Pull scheduled classes
        cursor.execute("""
            SELECT 
                sc.id, sc.scheduled_date, sc.approved, sc.cancelled, sc.room_slug, sc.room_name,
                sc.tutor_id, u1.first_name AS tutor_first, u1.last_name AS tutor_last,
                sc.student_id, u2.first_name AS student_first, u2.last_name AS student_last,
                sc.created_by_role
            FROM scheduled_classes sc
            JOIN users u1 ON sc.tutor_id = u1.user_id
            JOIN users u2 ON sc.student_id = u2.user_id
            WHERE sc.tutor_id = %s OR sc.student_id = %s
            ORDER BY sc.scheduled_date ASC
        """, (user_id, user_id))
        scheduled_classes = cursor.fetchall()

        # ✅ Tutor-specific
        if role == 'tutor':
            cursor.execute("""
                SELECT u.user_id, u.first_name, u.last_name, u.email, ps.parent_id
                FROM users u
                JOIN tutor_student ts ON u.user_id = ts.student_id
                LEFT JOIN parent_student ps ON u.user_id = ps.student_id
                WHERE ts.tutor_id = %s
            """, (user_id,))
            students = cursor.fetchall()

            cursor.execute("SELECT DISTINCT room_slug, room_name FROM invitations WHERE tutor_id = %s", (user_id,))
            classrooms = cursor.fetchall()

            if request.method == 'POST':
                if 'create_room' in request.form:
                    room_name = request.form.get('room_name')
                    room_slug = generate_room_slug(room_name)
                    student_ids = request.form.getlist('students')
                    try:
                        for student_id in student_ids:
                            cursor.execute(
                                "INSERT INTO invitations (tutor_id, student_id, room_name, room_slug) VALUES (%s, %s, %s, %s)",
                                (user_id, student_id, room_name, room_slug)
                            )
                        conn.commit()
                        flash(f"Classroom '{room_name}' created and students invited.")
                        logging.info(f"Tutor {user_id} created classroom: {room_name} with slug {room_slug}")
                    except Exception as e:
                        conn.rollback()
                        flash(f"Error creating classroom: {str(e)}")
                        logging.error(f"Error creating classroom for tutor {user_id}: {str(e)}")
                    return redirect(url_for('dashboard'))

        # ✅ Parent-specific
        elif role == 'parent':
            return redirect(url_for('parent_dashboard'))  # Early exit for parents
        
        # ✅ Student-specific
        else:
            cursor.execute("SELECT DISTINCT room_slug, room_name FROM invitations WHERE student_id = %s", (user_id,))
            classrooms = cursor.fetchall()
            conn.commit()
            students = None

        # ✅ Tutors (for students)
        cursor.execute("""
            SELECT DISTINCT u.user_id, u.first_name, u.last_name 
            FROM users u 
            JOIN tutor_student ts ON ts.tutor_id = u.user_id 
            WHERE ts.student_id = %s
        """, (user_id,))
        tutors = cursor.fetchall()

        # ✅ Invitations
        cursor.execute("""
            SELECT tutor_id, student_id, room_name 
            FROM invitations
            WHERE tutor_id = %s OR student_id = %s
        """, (user_id, user_id))
        all_invitations = cursor.fetchall()

        # ✅ Pending parent requests (only for students)
        if role == 'student':
            cursor.execute("""
                SELECT psr.id, u.first_name, u.last_name
                FROM parent_student_requests psr
                JOIN users u ON psr.parent_id = u.user_id
                WHERE psr.student_id = %s AND psr.status = 'pending'
            """, (user_id,))
            pending_parent_requests = cursor.fetchall()

        return render_template('dashboard.html', 
                               role=role, first_name=first_name, last_name=last_name, email=email, 
                               classrooms=classrooms, students=students, scheduled_classes=scheduled_classes, 
                               tutors=tutors, all_invitations=all_invitations, user_id=user_id, 
                               pending_parent_requests=pending_parent_requests)

    except Exception as e:
        logging.error(f"Error in dashboard for email {session['email']}: {str(e)}", exc_info=True)
        flash(f"Error loading dashboard: {str(e)}")
        return redirect(url_for('login'))

@app.route('/parent_dashboard')
def parent_dashboard():
    if 'email' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    # Get current parent ID
    cursor.execute("SELECT user_id, first_name FROM users WHERE email = %s", (session['email'],))
    user = cursor.fetchone()
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))
    parent_id, first_name = user

    # Find their linked students
    cursor.execute("""
        SELECT ps.student_id, u.first_name, u.last_name 
        FROM parent_student ps
        JOIN users u ON ps.student_id = u.user_id
        WHERE ps.parent_id = %s
    """, (parent_id,))
    students = cursor.fetchall()

    # Find each student's tutors
    student_tutors = {}
    for student in students:
        student_id = student[0]
        cursor.execute("""
            SELECT ts.tutor_id, u.first_name, u.last_name
            FROM tutor_student ts
            JOIN users u ON ts.tutor_id = u.user_id
            WHERE ts.student_id = %s
        """, (student_id,))
        tutors = cursor.fetchall()
        student_tutors[student_id] = tutors

    return render_template('parent_dashboard.html', first_name=first_name, students=students, student_tutors=student_tutors)

@app.route('/respond_parent_link', methods=['POST'])
def respond_parent_link():
    if 'email' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    request_id = request.form.get('request_id')
    action = request.form.get('action')

    if action == 'approve':
        # First get the parent_id and student_id
        cursor.execute("""
            SELECT parent_id, student_id 
            FROM parent_student_requests 
            WHERE id = %s
        """, (request_id,))
        link = cursor.fetchone()

        if link:
            parent_id, student_id = link

            # Insert into parent_student table (new permanent link)
            cursor.execute("""
                INSERT INTO parent_student (parent_id, student_id)
                VALUES (%s, %s)
            """, (parent_id, student_id))

            # Then mark the request as approved
            cursor.execute("""
                UPDATE parent_student_requests
                SET status = 'approved', approved_at = NOW()
                WHERE id = %s
            """, (request_id,))
            conn.commit()

            flash("Parent link approved successfully.")
        else:
            flash("Request not found.")
        
    elif action == 'reject':
        cursor.execute("""
            UPDATE parent_student_requests
            SET status = 'rejected'
            WHERE id = %s
        """, (request_id,))
        conn.commit()
        flash("Parent link request rejected.")

    return redirect(url_for('dashboard'))


@app.route('/view_class_chat/<int:student_id>/<int:tutor_id>')
def view_class_chat(student_id, tutor_id):
    if 'email' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    # Fetch student-tutor messages
    cursor.execute("""
        SELECT sender_id, content, timestamp
        FROM messages
        WHERE (sender_id = %s AND receiver_id = %s)
           OR (sender_id = %s AND receiver_id = %s)
        ORDER BY timestamp ASC
    """, (student_id, tutor_id, tutor_id, student_id))
    messages = cursor.fetchall()

    return render_template('view_class_chat.html', messages=messages)

# @app.route('/parent_message_tutor/<int:tutor_id>')
# def parent_message_tutor(tutor_id):
#     if 'email' not in session:
#         flash("Please log in.")
#         return redirect(url_for('login'))

#     # Find parent
#     cursor.execute("SELECT user_id FROM users WHERE email = %s", (session['email'],))
#     parent_id = cursor.fetchone()[0]

#     # Fetch existing chat messages
#     cursor.execute("""
#         SELECT sender_id, message, timestamp
#         FROM parent_tutor_chat
#         WHERE (parent_id = %s AND tutor_id = %s)
#         ORDER BY timestamp ASC
#     """, (parent_id, tutor_id))
#     messages = cursor.fetchall()

#     return render_template('chat.html', messages=messages, tutor_id=tutor_id, parent_id=parent_id)

@app.route('/remove_tutor', methods=['POST'])
def remove_tutor():
    if 'email' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    try:
        tutor_id = request.form.get('tutor_id')
        student_id = session.get('user_id')

        # 1. Delete from scheduled_classes
        cursor.execute("""
            DELETE FROM scheduled_classes 
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        # 2. Delete from invitations
        cursor.execute("""
            DELETE FROM invitations 
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        # 3. Delete from tutor_student mapping
        cursor.execute("""
            DELETE FROM tutor_student 
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        conn.commit()
        flash("Tutor removed and all related data deleted.")
        return redirect(url_for('dashboard'))
    except Exception as e:
        conn.rollback()
        flash(f"Error removing tutor: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/chat/<int:partner_id>', methods=['GET', 'POST'])
def chat(partner_id):
    if 'email' not in session:
        flash("Please log in to chat.")
        return redirect(url_for('login'))

    chat_type = request.args.get('chat_type', 'student')  # Default to student chat

    cursor.execute("SELECT user_id FROM users WHERE email = %s", (session['email'],))
    current_user_id = cursor.fetchone()[0]

    cursor.execute("SELECT user_id, first_name, last_name FROM users WHERE user_id = %s", (partner_id,))
    partner = cursor.fetchone()
    if not partner:
        flash("User not found.")
        return redirect(url_for('dashboard'))

    if chat_type == 'student':
        cursor.execute("""
            SELECT 1 FROM tutor_student 
            WHERE (tutor_id = %s AND student_id = %s) OR (tutor_id = %s AND student_id = %s)
        """, (partner_id, current_user_id, current_user_id, partner_id))
    elif chat_type == 'parent_tutor':
        cursor.execute("""
            SELECT 1
            FROM parent_student ps
            JOIN tutor_student ts ON ps.student_id = ts.student_id
            WHERE (ps.parent_id = %s AND ts.tutor_id = %s) OR (ps.parent_id = %s AND ts.tutor_id = %s)
        """, (current_user_id, partner_id, partner_id, current_user_id))

    relationship_exists = cursor.fetchone()
    if not relationship_exists:
        flash("Unauthorized access to chat.")
        return redirect(url_for('dashboard'))

    # Build the correct room
    if chat_type == 'student':
        room = f"studenttutor_{min(current_user_id, partner_id)}_{max(current_user_id, partner_id)}"
    elif chat_type == 'parent_tutor':
        room = f"parenttutor_{min(current_user_id, partner_id)}_{max(current_user_id, partner_id)}"

    # Handle POST (new message)
    if request.method == 'POST':
        message = request.form.get('message')
        timestamp = datetime.now()

        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content, timestamp, room)
            VALUES (%s, %s, %s, %s, %s)
        """, (current_user_id, partner_id, message, timestamp, room))
        conn.commit()

        return redirect(url_for('chat', partner_id=partner_id, chat_type=chat_type))

    # Handle GET (load previous messages)
    cursor.execute("""
        SELECT sender_id, content, timestamp 
        FROM messages
        WHERE room = %s
        ORDER BY timestamp ASC
    """, (room,))
    messages = cursor.fetchall()

    return render_template("chat.html", partner=partner, messages=messages, current_user_id=current_user_id, room=room)


@app.route('/schedule_class', methods=['POST'])
def schedule_class():
    if 'email' not in session:
        flash("Login required.")
        return redirect(url_for('login'))

    created_by = request.form['created_by']
    room_name = request.form['room_name']
    scheduled_date = request.form['scheduled_date']

    student_id_raw = request.form.get('student_id')
    tutor_id_raw = request.form.get('tutor_id')

    try:
        student_id = int(student_id_raw) if student_id_raw else None
        tutor_id = int(tutor_id_raw) if tutor_id_raw else None
    except ValueError:
        flash("Invalid tutor or student selection.")
        return redirect(url_for('dashboard'))

    if not student_id or not tutor_id:
        flash("Please select both a tutor and a student.")
        return redirect(url_for('dashboard'))

    # Fetch the room_slug using room_name, tutor_id, and student_id
    cursor.execute("""
        SELECT room_slug FROM invitations
        WHERE room_name = %s AND tutor_id = %s AND student_id = %s
    """, (room_name, tutor_id, student_id))
    result = cursor.fetchone()

    if not result:
        flash("Unable to find matching classroom invitation.")
        return redirect(url_for('dashboard'))

    room_slug = result[0]
    join_link = f"https://twotoro.com/classroom/{room_slug}"

    try:
        cursor.execute("""
            INSERT INTO scheduled_classes 
                (tutor_id, student_id, room_name, room_slug, scheduled_date, join_link, created_by_role)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (tutor_id, student_id, room_name, room_slug, scheduled_date, join_link, created_by))
        conn.commit()
        flash("Class scheduled. Awaiting approval.")
    except Exception as e:
        conn.rollback()
        flash(f"Error scheduling class: {str(e)}")

    return redirect(url_for('dashboard'))



@app.route('/approve_class', methods=['POST'])
def approve_class():
    class_id = request.form['class_id']
    try:
        cursor.execute("UPDATE scheduled_classes SET approved = TRUE WHERE id = %s", (class_id,))
        conn.commit()
        flash("Class approved.")
    except Exception as e:
        conn.rollback()
        flash(f"Approval failed: {e}")
    return redirect(url_for('dashboard'))


@app.route('/cancel_class', methods=['POST'])
def cancel_class():
    class_id = request.form['class_id']
    try:
        cursor.execute("UPDATE scheduled_classes SET cancelled = TRUE WHERE id = %s", (class_id,))
        conn.commit()
        flash("Class cancelled.")
    except Exception as e:
        conn.rollback()
        flash(f"Cancellation failed: {e}")
    return redirect(url_for('dashboard'))

@app.route('/classroom/<room_slug>')
def classroom(room_slug):
    logging.info(f"Accessing classroom with slug: {room_slug} for user email: {session.get('email')}")
    if 'email' not in session:
        flash("Please log in to access the classroom.")
        return redirect(url_for('login'))
    
    if '-' not in room_slug or len(room_slug) < 9:
        flash("Invalid classroom URL.")
        logging.warning(f"Invalid room_slug format: {room_slug}")
        return redirect(url_for('dashboard'))

    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed: {db_error}")
        flash("Database error. Please try again later.")
        return redirect(url_for('login'))

    try:
        cursor.execute("SELECT user_id, role, lifetime_free FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        if not user:
            flash("User not found.")
            logging.warning(f"User not found for email: {session['email']}")
            return redirect(url_for('login'))
        user_id, role, lifetime_free = user

        plan, status = get_user_subscription(user_id)
        if not lifetime_free and role != 'student' and plan == 2:
            now = datetime.utcnow()
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
            session_count = get_user_session_count(user_id, month_start, month_end)
            if session_count >= 4:
                flash("You’ve reached your free session limit (4 sessions/month). Please upgrade.")
                logging.info(f"User {user_id} reached free session limit")
                return redirect(url_for('upgrade'))

        if role == 'tutor':
            query = "SELECT 1 FROM invitations WHERE LOWER(room_slug) = LOWER(%s) AND tutor_id = %s"
        else:
            query = "SELECT 1 FROM invitations WHERE LOWER(room_slug) = LOWER(%s) AND student_id = %s"
        cursor.execute(query, (room_slug, user_id))
        if not cursor.fetchone():
            flash("You don’t have access to this room.")
            logging.warning(f"User {user_id} attempted to access unauthorized room: {room_slug}")
            return redirect(url_for('dashboard'))

        cursor.execute(
            "INSERT INTO sessions (user_id, start_time) VALUES (%s, %s) RETURNING session_id",
            (user_id, datetime.utcnow())
        )
        session['current_session_id'] = cursor.fetchone()[0]
        conn.commit()

        cursor.execute("SELECT room_name FROM invitations WHERE room_slug = %s LIMIT 1", (room_slug,))
        room_row = cursor.fetchone()
        room_name = room_row[0] if room_row else "Unknown Classroom"
        conn.commit()

        return render_template('classroom.html', roomName=room_name, room_slug=room_slug, user_id=user_id, userRole=role)
    except Exception as e:
        logging.error(f"Error in classroom for email {session['email']}: {str(e)}", exc_info=True)
        flash("An error occurred. Please try again.")
        return redirect(url_for('dashboard'))


@socketio.on('whiteboard')
def handle_whiteboard_event(data):
    room = data.get('room', 'defaultRoom')
    emit('whiteboard', data, room=room, include_self=True)

@app.route('/tutors')
def tutors():
    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for tutors: {db_error}")
        flash(db_error)
        return redirect(url_for('index'))

    try:
        # Fetch only active products
        cursor.execute("SELECT name, price, description, stripe_price_id, active FROM products WHERE active = TRUE ORDER BY price")
        products = cursor.fetchall()
        logging.info(f"Products fetched for tutors page: {products}")
        return render_template('tutors.html', products=products)
    except Exception as e:
        logging.error(f"Error in tutors page: {str(e)}", exc_info=True)
        flash(f"Error loading tutors page: {str(e)}")
        return redirect(url_for('index'))

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'email' not in session:
        flash("Please log in to update your password.")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for update_password: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
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
                logging.info(f"Password updated for email: {session['email']}")
            else:
                flash("Current password is incorrect.")
                logging.warning(f"Failed password update for email: {session['email']} - Invalid current password")
            return redirect(url_for('dashboard'))

        return render_template('update_password.html')
    except Exception as e:
        logging.error(f"Error in update_password for email {session['email']}: {str(e)}", exc_info=True)
        flash(f"Error updating password: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/update_info', methods=['GET', 'POST'])
def update_info():
    if 'email' not in session:
        flash("Please log in to update your information.")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for update_info: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        if request.method == 'POST':
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            cursor.execute("UPDATE users SET first_name = %s, last_name = %s WHERE email = %s", (first_name, last_name, session['email']))
            conn.commit()
            flash("Personal information updated successfully.")
            logging.info(f"Personal info updated for email: {session['email']}")
            return redirect(url_for('dashboard'))

        cursor.execute("SELECT first_name, last_name FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        return render_template('update_info.html', first_name=user[0], last_name=user[1])
    except Exception as e:
        logging.error(f"Error in update_info for email {session['email']}: {str(e)}", exc_info=True)
        flash(f"Error updating information: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/remove_student', methods=['POST'])
def remove_student():
    if 'email' not in session or session['role'] != 'tutor':
        flash("You must be a tutor to remove students.")
        return redirect(url_for('login'))

    db_status, db_error = check_db_connection()
    if not db_status:
        flash(db_error)
        return redirect(url_for('dashboard'))

    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (session['email'],))
        tutor_id = cursor.fetchone()[0]
        student_id = int(request.form.get('student_id'))

        # Remove scheduled classes
        cursor.execute("""
            DELETE FROM scheduled_classes
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        # Remove invitations
        cursor.execute("""
            DELETE FROM invitations
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        # Remove from tutor_student
        cursor.execute("""
            DELETE FROM tutor_student
            WHERE tutor_id = %s AND student_id = %s
        """, (tutor_id, student_id))

        conn.commit()
        flash("Student and all related data removed.")

    except Exception as e:
        conn.rollback()
        flash(f"Error removing student: {str(e)}")
        logging.error(f"Error removing student: {str(e)}", exc_info=True)

    return redirect(url_for('dashboard'))

@app.route('/assign_student', methods=['POST'])
def assign_student():
    if 'email' not in session or session['role'] != 'tutor':
        flash("You must be a tutor to assign students.")
        return redirect(url_for('login'))

    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"DB error in assign_student: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        # Get tutor ID
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (session['email'],))
        tutor_id = cursor.fetchone()[0]

        student_email = request.form.get('student_email')
        cursor.execute("SELECT user_id, first_name FROM users WHERE email = %s AND role = 'student'", (student_email,))
        student = cursor.fetchone()

        if student:
            student_id, student_first = student

            try:
                # Insert into tutor_student
                cursor.execute("INSERT INTO tutor_student (tutor_id, student_id) VALUES (%s, %s)", (tutor_id, student_id))
                conn.commit()
                flash(f"Student {student_email} assigned successfully.")
                logging.info(f"Tutor {tutor_id} assigned student {student_id}")
            except psycopg2.IntegrityError:
                conn.rollback()
                flash("Student is already assigned to you.")
                logging.warning(f"Duplicate assignment: Tutor {tutor_id} -> Student {student_email}")
                return redirect(url_for('dashboard'))

            # Auto-create classroom if not exists
            cursor.execute("SELECT first_name FROM users WHERE user_id = %s", (tutor_id,))
            tutor_first = cursor.fetchone()[0]

            room_name = f"{tutor_first}-{student_first} Class"
            room_slug = generate_room_slug(room_name)

            cursor.execute("""
                SELECT 1 FROM invitations WHERE tutor_id = %s AND student_id = %s
            """, (tutor_id, student_id))

            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO invitations (tutor_id, student_id, room_name, room_slug)
                    VALUES (%s, %s, %s, %s)
                """, (tutor_id, student_id, room_name, room_slug))
                conn.commit()
                flash(f"Classroom '{room_name}' created for {student_first}.")
            else:
                logging.info(f"Classroom already exists for Tutor {tutor_id} and Student {student_id}")

        else:
            flash("Student not found.")
            logging.warning(f"Student not found: {student_email}")

        return redirect(url_for('dashboard'))

    except Exception as e:
        logging.error(f"Error assigning student: {str(e)}", exc_info=True)
        flash(f"Error assigning student: {str(e)}")
        return redirect(url_for('dashboard'))


@app.route('/upgrade', methods=['GET', 'POST'])
def upgrade():
    if 'email' not in session:
        flash("Please log in to upgrade your plan.")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for upgrade: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
        cursor.execute("SELECT user_id, early_adopter, lifetime_free FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        user_id, early_adopter, lifetime_free = user

        if lifetime_free:
            flash("You already have a lifetime free subscription with all benefits!")
            return redirect(url_for('dashboard'))

        # Fetch active products to determine available plans
        cursor.execute("SELECT product_id, name, price, description, stripe_price_id, active FROM products WHERE active = TRUE AND name != %s", (FREE_PLAN,))
        products = cursor.fetchall()
        logging.info(f"Products fetched for upgrade: {products}")

        if request.method == 'POST':
            # Retrieve the selected plan from the form
            selected_plan = request.form.get('selected_plan')
            logging.info(f"Selected plan for upgrade by user_id {user_id}: {selected_plan}")
            if not selected_plan:
                flash("Please select a plan to upgrade.")
                return redirect(url_for('upgrade'))

            # Find the selected product
            selected_product = next((product for product in products if product[0] == int(selected_plan)), None)
            if not selected_product:
                flash("Selected plan not found.")
                return redirect(url_for('upgrade'))

            price_id = selected_product[4]  # stripe_price_id
            product_name = selected_product[1]

            # Build a dynamic statement descriptor
            descriptor = f"TwoToro {product_name}"
            max_length = 22
            if len(descriptor) > max_length:
                descriptor = descriptor[:max_length].rstrip()

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
                        'statement_descriptor': descriptor
                    }
                )
                logging.info(f"Checkout session created for upgrade by user_id {user_id}: {checkout_session.id}")
                return redirect(checkout_session.url, code=303)
            except Exception as e:
                logging.error(f"Error creating checkout session for upgrade by user_id {user_id}: {str(e)}", exc_info=True)
                flash(f"Error creating checkout session: {str(e)}")
                return redirect(url_for('upgrade'))

        return render_template('upgrade.html', stripe_publishable_key=STRIPE_PUBLISHABLE_KEY, products=products)
    except Exception as e:
        logging.error(f"Error in upgrade for email {session['email']}: {str(e)}", exc_info=True)
        flash(f"Error loading upgrade page: {str(e)}")
        return redirect(url_for('login'))

# socket stuff

@socketio.on('parent_send_message')
def handle_parent_send_message(data):
    parent_id = data['parent_id']
    tutor_id = data['tutor_id']
    message = data['message']
    room = data['room']  # e.g., "parenttutor_4_9"

    timestamp = datetime.now()

    # Insert into the shared messages table
    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, content, timestamp, room)
        VALUES (%s, %s, %s, %s, %s)
    """, (parent_id, tutor_id, message, timestamp, room))
    conn.commit()

    emit('receive_message', {
        'sender_id': parent_id,
        'message': message,
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M')
    }, room=room, include_self=True)  # ✅ This makes it show up immediately for sender too

@socketio.on('join_parent_chat')
def handle_join_parent_chat(data):
    parent_id = data['parent_id']
    tutor_id = data['tutor_id']
    room = f"parenttutor_{min(parent_id, tutor_id)}_{max(parent_id, tutor_id)}"
    join_room(room)

@socketio.on('join_chat')
def handle_join_chat(data):
    room = data['room']
    join_room(room)

# For student-tutor chat
@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    message = data['message']
    room = data['room']
    timestamp = datetime.now()

    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, content, timestamp, room)
        VALUES (%s, %s, %s, %s, %s)
    """, (sender_id, receiver_id, message, timestamp, room))
    conn.commit()

    emit('receive_message', {
        'sender_id': sender_id,
        'message': message,
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M')
    }, room=room, include_self=True)  # 👈 INCLUDE YOURSELF!

@socketio.on('typing')
def handle_typing(data):
    emit('show_typing', data, room=data['room'])

@socketio.on('ping')
def handle_ping():
    emit('pong')

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    user_id = data.get('user_id')
    sid = request.sid

    if not room or not user_id:
        logging.warning(f"Invalid join request: room={room}, user_id={user_id}, sid={sid}")
        return

    join_room(room)
    # Assume add_user_to_room is a helper function to track users
    add_user_to_room(user_id, room)

    room_members = socketio.server.manager.rooms.get('/', {}).get(room, set())
    user_count = len(room_members)

    logging.info(f"User {sid} (user_id={user_id}) joined room: {room}, total users: {user_count}")
    role = 'offerer' if user_count == 1 else 'answerer'
    emit('role', {'role': role}, to=sid)

    if user_count == 2:
        emit('start_session', room=room)  # Tell both users to start the session
    else:
        emit('user-joined', {'msg': 'A new user has joined!'}, room=room, skip_sid=sid)

@socketio.on('connect')
def on_connect():
    sid = request.sid
    logging.info(f"User {sid} connected to Socket.IO")

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    logging.info(f"User {sid} disconnected from Socket.IO")

@socketio.on('rejoin_all')
def handle_rejoin_all(data):
    user_id = data.get('user_id')
    if not user_id:
        logging.warning("Rejoin request missing user_id")
        return

    rooms = get_user_rooms(user_id)
    for room in rooms:
        join_room(room)
        logging.info(f"User {user_id} rejoined room {room}")

@socketio.on('signal')
def handle_signal(data):
    room = data.get('room')
    if not room:
        logging.warning("Signal received without room specified.")
        return
    logging.info(f"Incoming WebRTC signal for room {room}: {data}")
    emit('signal', data, room=room, include_self=True)  # Include sender to handle self-updates
    logging.info(f"Emitted WebRTC signal to room {room}")


@socketio.on('session_update')
def on_session_update(data):
    if 'user_id' not in session or 'current_session_id' not in session:
        return

    try:
        duration = data.get('duration', 0)
        cursor.execute(
            "UPDATE sessions SET duration = %s WHERE session_id = %s",
            (duration, session['current_session_id'])
        )
        conn.commit()
        logging.info(f"Session updated for user_id {session['user_id']}: duration {duration}")
    except Exception as e:
        logging.error(f"Error updating session for user_id {session['user_id']}: {str(e)}", exc_info=True)

# Only used when running locally
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
    # socketio.run(app, host='127.0.0.1', port=8080, debug=True)

def shutdown():
    try:
        cursor.close()
        conn.close()
        logging.info("Database connection closed")
    except Exception as e:
        logging.error(f"Error closing database connection: {str(e)}")
import atexit
atexit.register(shutdown)