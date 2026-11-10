from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import psycopg2
import psycopg2.extras
from route_trace import run_manual_traceroute

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'

# פרטי ההתחברות ל-PostgreSQL (עדכן את הסיסמה שלך כאן)
DB_HOST = "localhost"
DB_NAME = "pufferfish_db"
DB_USER = "postgres"
DB_PASS = "1234"

def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS "user" (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(200) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username = %s OR email = %s', (identifier, identifier))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username, email, or password.'
            
    return render_template('auth.html', mode='login', error=error)

@app.route('/home')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            error = 'Passwords do not match.'
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                hashed_password = generate_password_hash(password)
                cursor.execute('INSERT INTO "user" (username, email, password_hash) VALUES (%s, %s, %s)',
                             (username, email, hashed_password))
                conn.commit()
                cursor.close()
                conn.close()
                return redirect(url_for('login'))
            except psycopg2.errors.UniqueViolation:
                error = 'Username or email already exists.'
                
    return render_template('auth.html', mode='register', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    traceroute_results = []
    target_host = None
    
    if request.method == 'POST':
        target_host = request.form.get('target', '').strip()
        if target_host:
            traceroute_results = run_manual_traceroute(target_host)
        
    return render_template('dashboard.html', username=session['username'], results=traceroute_results, target=target_host)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin123':
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        error = 'Invalid admin credentials.'
    return render_template('admin_login.html', error=error, csrf_token='secret_csrf')

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('SELECT * FROM "user"')
    raw_users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    users = []
    for u in raw_users:
        user_data = dict(u)
        if isinstance(user_data['created_at'], str):
            try:
                user_data['created_at'] = datetime.strptime(user_data['created_at'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass
        users.append(user_data)

    return render_template('admin.html', users=users, csrf_token='secret_csrf')

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM "user" WHERE id = %s', (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)