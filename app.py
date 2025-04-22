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
            if role not in ['tutor', 'student']:
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


        if role == 'tutor':
            cursor.execute("SELECT u.user_id, u.first_name, u.last_name, u.email "
                          "FROM users u JOIN tutor_student ts ON u.user_id = ts.student_id "
                          "WHERE ts.tutor_id = %s", (user_id,))
            students = cursor.fetchall()

            cursor.execute("SELECT DISTINCT room_slug, room_name FROM invitations WHERE tutor_id = %s", (user_id,))
            classrooms = cursor.fetchall()
            conn.commit()

            cursor.execute("SELECT u.user_id, u.first_name, u.last_name FROM users u JOIN tutor_student ts ON u.user_id = ts.student_id WHERE ts.tutor_id = %s", (user_id,))
            students = cursor.fetchall()

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

        else:
            cursor.execute("SELECT DISTINCT room_slug, room_name FROM invitations WHERE student_id = %s", (user_id,))
            classrooms = cursor.fetchall()  # Check student_id, not tutor_id
            conn.commit()
            students = None
        
        # print("Classrooms:", classrooms)

        cursor.execute("SELECT DISTINCT u.user_id, u.first_name, u.last_name FROM users u JOIN tutor_student ts ON ts.tutor_id = u.user_id WHERE ts.student_id = %s", (user_id,))
        tutors = cursor.fetchall()

        cursor.execute("""
            SELECT tutor_id, student_id, room_name 
            FROM invitations
            WHERE tutor_id = %s OR student_id = %s
        """, (user_id, user_id))
        all_invitations = cursor.fetchall()

        return render_template('dashboard.html', role=role, first_name=first_name, last_name=last_name, email=email, 
                               classrooms=classrooms, students=students, scheduled_classes=scheduled_classes, 
                               tutors=tutors, all_invitations=all_invitations, user_id=user_id)
    except Exception as e:
        logging.error(f"Error in dashboard for email {session['email']}: {str(e)}", exc_info=True)
        flash(f"Error loading dashboard: {str(e)}")
        return redirect(url_for('login'))


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
    # Check if user is logged in
    if 'email' not in session:
        flash("Please log in to access the classroom.")
        return redirect(url_for('login'))
    
    if '-' not in room_slug or len(room_slug) < 9:  # Minimum length for name-UUID
        flash("Invalid classroom URL.")
        logging.warning(f"Invalid room_slug format: {room_slug}")
        return redirect(url_for('dashboard'))

    # Verify database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed: {db_error}")
        flash("Database error. Please try again later.")
        return redirect(url_for('login'))

    try:
        # Fetch user details
        cursor.execute("SELECT user_id, role, lifetime_free FROM users WHERE email = %s", (session['email'],))
        user = cursor.fetchone()
        if not user:
            flash("User not found.")
            logging.warning(f"User not found for email: {session['email']}")
            return redirect(url_for('login'))
        user_id, role, lifetime_free = user

        # Check session limits for non-students without lifetime free access
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

        # Verify room access using room_slug instead of room_name
        if role == 'tutor':
            query = "SELECT 1 FROM invitations WHERE LOWER(room_slug) = LOWER(%s) AND tutor_id = %s"
        else:
            query = "SELECT 1 FROM invitations WHERE LOWER(room_slug) = LOWER(%s) AND student_id = %s"
        cursor.execute(query, (room_slug, user_id))
        if not cursor.fetchone():
            flash("You don’t have access to this room.")
            logging.warning(f"User {user_id} attempted to access unauthorized room: {room_slug}")
            return redirect(url_for('dashboard'))

        # Start session tracking
        cursor.execute(
            "INSERT INTO sessions (user_id, start_time) VALUES (%s, %s) RETURNING session_id",
            (user_id, datetime.utcnow())
        )
        session['current_session_id'] = cursor.fetchone()[0]
        conn.commit()

        # Fetch the friendly room name using the room_slug
        cursor.execute("SELECT room_name FROM invitations WHERE room_slug = %s LIMIT 1", (room_slug,))
        room_row = cursor.fetchone()
        room_name = room_row[0] if room_row else "Unknown Classroom"
        conn.commit()
        # Render classroom
        return render_template('classroom.html', roomName=room_name, userPlan=plan, userRole=role)

    except Exception as e:
        logging.error(f"Error in classroom for email {session['email']}: {str(e)}", exc_info=True)
        flash("An error occurred. Please try again.")
        return redirect(url_for('dashboard'))


@socketio.on('whiteboard')
def handle_whiteboard_event(data):
    # Assuming you have a way to identify the room,
    # you could attach the room name to the data payload or determine it from the session.
    room = data.get('room', 'defaultRoom')
    # Broadcast the drawing event to all users except the one who emitted it
    emit('whiteboard', data, room=room, include_self=False)

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

@app.route('/assign_student', methods=['POST'])
def assign_student():
    if 'email' not in session or session['role'] != 'tutor':
        flash("You must be a tutor to assign students.")
        return redirect(url_for('login'))

    # Check database connection
    db_status, db_error = check_db_connection()
    if not db_status:
        logging.error(f"Database connection failed for assign_student: {db_error}")
        flash(db_error)
        return redirect(url_for('login'))

    try:
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
                logging.info(f"Tutor {tutor_id} assigned student {student[0]}")
            except psycopg2.IntegrityError:
                conn.rollback()
                flash("Student is already assigned to you.")
                logging.warning(f"Tutor {tutor_id} failed to assign student {student_email} - Already assigned")
        else:
            flash("Student not found.")
            logging.warning(f"Tutor {tutor_id} failed to assign student {student_email} - Student not found")
        return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error(f"Error in assign_student for email {session['email']}: {str(e)}", exc_info=True)
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

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    sid = request.sid
    if room:
        join_room(room)

        # Get the current number of users in this room explicitly
        room_members = socketio.server.manager.rooms.get('/', {}).get(room, set())
        user_count = len(room_members)

        logging.info(f"User {sid} joined room: {room}, total users now: {user_count}")

        # First user becomes offerer
        if user_count == 1:
            emit('role', {'role': 'offerer'}, room=sid)
        else:
            emit('role', {'role': 'answerer'}, room=sid)

        emit('user-joined', {'msg': 'A new user has joined the room!'}, room=room)

@socketio.on('disconnect')
def on_disconnect():
    pass

@socketio.on('signal')
def handle_signal(data):
    room = data.get('room')
    if room:
        logging.info(f"Incoming WebRTC signal: {data}")
        emit('signal', data, room=room, include_self=False)
        logging.info(f"Emitted WebRTC signal to room {room}")
    else:
        logging.warning("Signal received without room specified.")


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