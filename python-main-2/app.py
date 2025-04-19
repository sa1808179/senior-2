# app.py
import random
import re
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from config import SECRET_KEY, DATABASE
import jwt
import datetime
from db.database import init_db, connect_db
from langchain_groq import ChatGroq
from populate import hash_password
from prompts import SYSTEM
import hashlib

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize the database
init_db()

# -- Helper to decode JWT and fetch user info --
def get_current_user():
    token = session.get('token')
    if not token:
        return None
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return decoded
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# -- Routes --
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve submitted form values
        username = request.form.get('user', '').strip()
        password = request.form.get('password', '')
        otp_input = request.form.get('otp')
        # Determine if we are in OTP stage
        otp_stage = 'otp' in request.form

        # First stage: credentials only
        if not otp_stage:
            if not (username and password):
                return render_template('login.html', error='Username and password required', otp_required=False)

            # Hash and verify credentials
            hashed_pw = hash_password(password)
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT user_id, username, isadmin FROM Users WHERE username = ? AND password = ?',
                (username, hashed_pw)
            )
            user = cursor.fetchone()
            conn.close()

            if not user:
                return render_template('login.html', error='Invalid username or password', otp_required=False)

            user_id, user_name, isadmin = user
            # Generate OTP, store in session, print to console
            otp_code = f"{random.randint(100000,999999)}"
            session['otp_value'] = otp_code
            session['pending_user'] = {
                'user_id': user_id,
                'username': user_name,
                'isadmin': isadmin
            }
            print(f"OTP for {user_name} (role {isadmin}): {otp_code}")
            # Prompt for OTP input
            return render_template('login.html', otp_required=True)

        # Second stage: OTP verification
        else:
            saved = session.get('pending_user')
            saved_otp = session.get('otp_value')
            if not saved or not saved_otp:
                # Missing session data, restart login
                return render_template('login.html', error='Session expired. Please login again.', otp_required=False)

            if not otp_input or otp_input != saved_otp:
                # Invalid OTP
                return render_template('login.html', error='Invalid OTP! Try again.', otp_required=True)

            # OTP valid: issue JWT
            session.pop('otp_value', None)
            session.pop('pending_user', None)
            token = jwt.encode({
                'user_id': saved['user_id'],
                'username': saved['username'],
                'isadmin': saved['isadmin'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            session['token'] = token
            return redirect(url_for('dashboard'))

    # GET request: show credentials form
    return render_template('login.html', otp_required=False)


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    # 1. All fields required
    if not (username and email and password):
        return render_template('login.html', error='All fields are required!')

    # 2. Email must be qu.edu.qa
    if not email.endswith('@qu.edu.qa'):
        return render_template('login.html', error='Email must end with @qu.edu.qa')

    # 3. Password policy: 8+ chars, one special
    if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return render_template(
            'login.html',
            error='Password must be at least 8 characters long and include a special character'
        )

    # 4. Hash the password
    hashed = hash_password(password)

    conn = connect_db()
    cursor = conn.cursor()

    # 5. Unique username/email
    cursor.execute(
        'SELECT 1 FROM Users WHERE email = ? OR username = ?',
        (email, username)
    )
    if cursor.fetchone():
        conn.close()
        return render_template('login.html', error='Email or Username already exists!')

    # 6. Insert
    cursor.execute(
        'INSERT INTO Users (username, email, password) VALUES (?, ?, ?)',
        (username, email, hashed)
    )
    conn.commit()
    conn.close()

    return render_template('login.html', success='User registered successfully!')

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE username = ?', (user['username'],))
    row = cursor.fetchone()
    conn.close()
    isadmin = bool(row[0]) if row else False
    return render_template('dashboard.html', username=user['username'], isadmin=isadmin)

@app.route('/faqs')
def faqs():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE username = ?', (user['username'],))
    row = cursor.fetchone()
    conn.close()
    isadmin = bool(row[0]) if row else False
    return render_template('faqs.html', username=user['username'], isadmin=isadmin)

@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    # Fetch advisors and admin status
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT advisor_id, name FROM Advisors')
    advisors = cursor.fetchall()
    cursor.execute('SELECT isadmin FROM Users WHERE username = ?', (user['username'],))
    row = cursor.fetchone()
    isadmin = bool(row[0]) if row else False

    if request.method == 'POST':
        advisor_id = request.form.get('advisor_id')
        appointment_date = request.form.get('appointment_date')
        time_slot = request.form.get('time_slot')
        if not (advisor_id and appointment_date and time_slot):
            conn.close()
            return render_template('book_appointment.html', error='All fields are required!',
                                   username=user['username'], isadmin=isadmin, advisors=advisors)
        cursor.execute(
            'SELECT slot_id FROM Time_Slots WHERE advisor_id = ? AND available_date = ? '
            'AND time_slot = ? AND is_booked = 0',
            (advisor_id, appointment_date, time_slot)
        )
        slot = cursor.fetchone()
        if not slot:
            conn.close()
            return render_template('book_appointment.html', error='Time slot not available!',
                                   username=user['username'], isadmin=isadmin, advisors=advisors)
        slot_id = slot[0]
        cursor.execute('UPDATE Time_Slots SET is_booked = 1 WHERE slot_id = ?', (slot_id,))
        cursor.execute(
            'INSERT INTO Appointments (student_id, slot_id, advisor_id) VALUES (?, ?, ?)',
            (user['user_id'], slot_id, advisor_id)
        )
        conn.commit()
        conn.close()
        return render_template('book_appointment.html', success='Appointment booked!',
                               username=user['username'], isadmin=isadmin, advisors=advisors)

    # GET
    cursor.execute('SELECT slot_id, available_date, time_slot FROM Time_Slots WHERE is_booked = 0')
    slots = cursor.fetchall()
    conn.close()
    return render_template('book_appointment.html', username=user['username'], isadmin=isadmin,
                           advisors=advisors, slots=slots)

@app.route('/api/advisors', methods=['GET'])
def get_advisors():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT advisor_id, name FROM Advisors')
    advisors = cursor.fetchall()
    conn.close()
    return jsonify([{'id': a[0], 'name': a[1]} for a in advisors])

@app.route('/api/available_slots', methods=['GET'])
def get_available_slots():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT slot_id, available_date, time_slot, advisor_id FROM Time_Slots WHERE is_booked = 0')
    slots = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': s[0], 'available_date': s[1], 'time_slot': s[2], 'advisor_id': s[3]}
        for s in slots
    ])

@app.route('/api/book_appointment', methods=['POST'])
def book_appointment_api():
    data = request.json
    student_id = data.get('student_id')
    advisor_id = data.get('advisor_id')
    appointment_date = data.get('appointment_date')
    time_slot = data.get('time_slot')
    if not (student_id and advisor_id and appointment_date and time_slot):
        return jsonify({'error': 'All fields are required'}), 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT slot_id FROM Time_Slots WHERE advisor_id = ? AND available_date = ? '
        'AND time_slot = ? AND is_booked = 0',
        (advisor_id, appointment_date, time_slot)
    )
    slot = cursor.fetchone()
    if not slot:
        conn.close()
        return jsonify({'error': 'Time slot not available'}), 400
    slot_id = slot[0]
    cursor.execute('UPDATE Time_Slots SET is_booked = 1 WHERE slot_id = ?', (slot_id,))
    cursor.execute(
        'INSERT INTO Appointments (student_id, slot_id, advisor_id) VALUES (?, ?, ?)',
        (student_id, slot_id, advisor_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'message': 'Booked successfully!'}), 201

@app.route('/api/slots', methods=['GET'])
def get_slots():
    advisor_id = request.args.get('advisor_id')
    date = request.args.get('date')
    if not (advisor_id and date):
        return jsonify({'error': 'Missing advisor_id or date'}), 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT time_slot FROM Time_Slots WHERE advisor_id = ? AND available_date = ? AND is_booked = 0',
        (advisor_id, date)
    )
    times = cursor.fetchall()
    conn.close()
    return jsonify([{'time_slot': t[0]} for t in times])

# -- Admin Panel --
@app.route('/admin')
def admin_dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    isadmin = bool(cursor.fetchone()[0])
    conn.close()
    return render_template('admin.html', username=user['username'], isadmin=isadmin)

# -- Users Management --
@app.route('/users')
def users():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('partials/users.html')

@app.route('/api/users_data')
def get_users_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id, username, email, isadmin FROM Users')
    users = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': u[0], 'username': u[1], 'email': u[2], 'isadmin': bool(u[3])}
        for u in users
    ])

@app.route('/api/toggle_admin', methods=['POST'])
def toggle_admin():
    user_id = request.form.get('user_id')
    if not user_id:
        return 'User ID required', 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return 'User not found', 404
    new_status = 0 if row[0] else 1
    cursor.execute('UPDATE Users SET isadmin = ? WHERE user_id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('users'))

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    user_id = request.form.get('user_id')
    if not user_id:
        return 'User ID required', 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('users'))

# -- Appointments Management --
@app.route('/appointments')
def appointments():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('partials/appointments.html')

@app.route('/api/appointments_data')
def get_appointments_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.appointment_id,
               u.username AS student,
               adv.name AS advisor,
               ts.available_date AS appointment_date,
               ts.time_slot
        FROM Appointments a
        LEFT JOIN Users u ON a.student_id = u.user_id
        LEFT JOIN Advisors adv ON a.advisor_id = adv.advisor_id
        LEFT JOIN Time_Slots ts ON a.slot_id = ts.slot_id
    ''')
    appts = cursor.fetchall()
    conn.close()
    return jsonify([
        {
            'id': row[0],
            'student': row[1] or 'Unknown',
            'advisor': row[2] or 'Unknown',
            'date': row[3],
            'time_slot': row[4]
        }
        for row in appts
    ])

@app.route('/api/delete_appointment', methods=['POST'])
def delete_appointment():
    appt_id = request.form.get('appointment_id')
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Appointments WHERE appointment_id = ?', (appt_id,))
    conn.commit()
    conn.close()
    return render_template('partials/appointments.html', success='Deleted successfully')

@app.route('/addappointmentslots')
def addappointmentslots():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    cursor.execute('SELECT advisor_id, name FROM Advisors')
    advisors = cursor.fetchall()
    conn.close()
    return render_template('partials/addappointmentslot.html', advisors=advisors)

@app.route('/api/add_slots', methods=['POST'])
def add_slots():
    advisor_id = request.form.get('advisor_id')
    available_date = request.form.get('available_date')
    time_slot = request.form.get('time_slot')
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO Time_Slots (advisor_id, available_date, time_slot, is_booked) VALUES (?, ?, ?, 0)',
                       (advisor_id, available_date, time_slot))
        conn.commit()
        cursor.execute('SELECT advisor_id, name FROM Advisors')
        advisors = cursor.fetchall()
        conn.close()
        return render_template('partials/addappointmentslot.html', success='Slot added!', advisors=advisors)
    except Exception as e:
        conn.close()
        return render_template('partials/addappointmentslot.html', error=str(e))

@app.route('/adddoctor')
def adddoctor():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('partials/adddoctor.html')

@app.route('/api/add_doctor', methods=['POST'])
def add_doctor():
    name = request.form.get('name')
    specialization = request.form.get('specialization')
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO Advisors (name, specialization) VALUES (?, ?)', (name, specialization))
        conn.commit()
        conn.close()
        return render_template('partials/adddoctor.html', success='Doctor added!')
    except Exception as e:
        conn.close()
        return render_template('partials/adddoctor.html', error=str(e))

@app.route('/courses')
def courses():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('partials/viewallcourses.html')

@app.route('/api/courses_data', methods=['GET'])
def courses_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT course_id, course_name, description FROM Courses')
    courses = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': c[0], 'course_name': c[1], 'description': c[2]} for c in courses
    ])

@app.route('/addcourse')
def addcourse():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
    if not cursor.fetchone()[0]:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('partials/addcourse.html')

@app.route('/updatecourse/<int:course_id>', methods=['GET'])
def updatecourse(course_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT course_name, description FROM Courses WHERE course_id = ?', (course_id,))
    course = cursor.fetchone()
    conn.close()
    if not course:
        return render_template('partials/updatecourse.html', error='Course not found')
    return render_template('partials/updatecourse.html', course_id=course_id,
                                   course_name=course[0], description=course[1])

@app.route('/api/update_course/<int:course_id>', methods=['POST'])
def update_course_api(course_id):
    course_name = request.form.get('course_name')
    description = request.form.get('description')
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE Courses SET course_name = ?, description = ? WHERE course_id = ?',
                       (course_name, description, course_id))
        conn.commit()
        conn.close()
        return render_template('partials/viewallcourses.html', success='Course updated!')
    except Exception as e:
        conn.close()
        return render_template('partials/viewallcourses.html', error=str(e))

# -- Chat Management --
@app.route('/api/ask', methods=['POST'])
def ask_question():
    data = request.json
    session_id = data.get('chat_id', 0)
    question = data.get('question', '').strip()
    if not question:
        return jsonify({'error': 'Question is required'}), 400
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    # Generate response via ChatGroq
    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0,
                   api_key="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")
    messages = [("system", SYSTEM), ("human", question)]
    ai_msg = llm.invoke(messages)
    # Save session and chat
    conn = connect_db()
    cursor = conn.cursor()
    if session_id == 0:
        cursor.execute('INSERT INTO Chat_Sessions (user_id) VALUES (?)', (user['user_id'],))
        session_id = cursor.lastrowid
    cursor.execute(
        'INSERT INTO Chats (user_id, session_id, user_message, bot_response) VALUES (?, ?, ?, ?)',
        (user['user_id'], session_id, question, ai_msg.content)
    )
    conn.commit()
    conn.close()
    return jsonify({'chat_id': session_id, 'question': question, 'answer': ai_msg.content})

@app.route('/api/chat_sessions', methods=['GET'])
def get_chat_sessions():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT session_id, name, created_at FROM Chat_Sessions WHERE user_id = ? ORDER BY created_at DESC',
        (user['user_id'],)
    )
    sessions = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': s[0], 'name': s[1] or 'New Chat', 'created_at': s[2]}
        for s in sessions
    ])

@app.route('/api/chat/<int:session_id>', methods=['GET'])
def get_chat(session_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT user_message, bot_response, timestamp FROM Chats WHERE session_id = ? AND user_id = ? ORDER BY timestamp ASC',
        (session_id, user['user_id'])
    )
    chats = cursor.fetchall()
    conn.close()
    return jsonify([
        {'user_message': c[0], 'bot_response': c[1], 'timestamp': c[2]}
        for c in chats
    ])

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0' , port=3000, debug=True)
