from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a secure key in production
socketio = SocketIO(app, cors_allowed_origins="*")

# Hard-coded user for demonstration purposes
USER_DATA = {
    "username": "admin",
    "password": "password123"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USER_DATA.get('username') and password == USER_DATA.get('password'):
            session['username'] = username
            return redirect(url_for('select_classroom'))
        else:
            flash("Invalid credentials. Please try again.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/select_classroom', methods=['GET', 'POST'])
def select_classroom():
    # Ensure the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        return redirect(url_for('classroom', room_name=room_name))
    return render_template('select_classroom.html')

@app.route('/classroom/<room_name>')
def classroom(room_name):
    # Ensure the user is logged in before accessing the classroom
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('classroom.html', roomName=room_name)

# Socket.IO events for WebRTC signaling
@socketio.on('join')
def on_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        print(f"User joined room: {room}")
        # Broadcast to everyone in the room that a new user has joined
        emit('user-joined', {'msg': 'A new user has joined the room!'}, room=room)


@socketio.on('signal')
def handle_signal(data):
    room = data.get('room')
    if room:
        emit('signal', data, room=room, include_self=False)


if __name__ == '__main__':
    # For local development
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
else:
    # For Render (production)
    port = int(os.environ.get('PORT', 8080))  # Use Render’s PORT or fallback
    socketio.run(app, host='0.0.0.0', port=port)
