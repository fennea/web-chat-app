from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import psycopg2
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# PostgreSQL connection (local default for macOS Homebrew)
DB_URL = os.environ.get('DATABASE_URL', 'postgres://anthonyfenner@localhost:5432/chitchat_db')
conn = psycopg2.connect(DB_URL)
cursor = conn.cursor()

# Rest of your code remains unchanged...
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        cursor.execute("SELECT username, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
            session['username'] = username
            return redirect(url_for('select_classroom'))
        else:
            flash("Invalid credentials. Please try again.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        role = request.form.get('role')  # Add the role field

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, username, password, role) VALUES (%s, %s, %s, %s, %s, %s)",
                (first_name, last_name, email, username, hashed_pw.decode('utf-8'), role)
            )
            conn.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Username or email already exists.")
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/select_classroom', methods=['GET', 'POST'])
def select_classroom():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        return redirect(url_for('classroom', room_name=room_name))
    return render_template('select_classroom.html')

@app.route('/classroom/<room_name>')
def classroom(room_name):
    if 'username' not in session:
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