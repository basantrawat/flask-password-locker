import os
import base64
import pyotp
import qrcode
import io
import csv
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import errorcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from zxcvbn import zxcvbn

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# Load keys from environment variables
MASTER_SECRET_KEY = os.environ.get('MASTER_SECRET_KEY', 'default_master_key').encode()

# Database configuration from environment variables
db_config = {
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'port': os.environ.get('DB_PORT', 3306),
    'database': os.environ.get('DB_NAME', 'pass_locker'),
    'autocommit': True
}

def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(**db_config)
        except mysql.connector.Error as err:
            print(f"Database connection error: {err}")
            g.db = None
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    db = get_db()
    if db:
        try:
            cursor = db.cursor(dictionary=True)
            cursor.execute(query, args)
            rv = cursor.fetchall()
            cursor.close()
            return (rv[0] if rv else None) if one else rv
        except Exception as e:
            print(f"Query error: {e}")
            return None
    return None

def insert_db(query, args=()):
    db = get_db()
    if db:
        try:
            cursor = db.cursor()
            cursor.execute(query, args)
            db.commit()
            last_id = cursor.lastrowid
            cursor.close()
            return last_id
        except Exception as e:
            print(f"Insert error: {e}")
            return None
    return None

def update_db(query, args=()):
    db = get_db()
    if db:
        try:
            cursor = db.cursor()
            cursor.execute(query, args)
            db.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"Update error: {e}")
            return False
    return False

def delete_db(query, args=()):
    db = get_db()
    if db:
        try:
            cursor = db.cursor()
            cursor.execute(query, args)
            db.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"Delete error: {e}")
            return False
    return False

def get_user_id():
    if 'username' in session:
        user = query_db('SELECT u_id FROM user_details WHERE email_id = %s', (session['username'],), one=True)
        if user:
            return user['u_id']
    return None

def derive_key(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(MASTER_SECRET_KEY))

def encrypt_pass(salt, password):
    key = derive_key(salt)
    f = Fernet(key)
    encrypted_pass = f.encrypt(password.encode('utf-8'))
    return encrypted_pass

def decrypt_pass(salt, encrypted_password):
    key = derive_key(salt)
    f = Fernet(key)
    try:
        decrypted_pass = f.decrypt(encrypted_password)
        return decrypted_pass.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return "[DECRYPTION FAILED]" 

# --- Tagging Helper Functions ---
def get_tag_id(tag_name):
    tag = query_db("SELECT tag_id FROM tags WHERE tag_name = %s", (tag_name,), one=True)
    if tag:
        return tag['tag_id']
    else:
        new_tag_id = insert_db("INSERT INTO tags (tag_name) VALUES (%s)", (tag_name,))
        return new_tag_id

def save_credential_tags(sno, tags_list):
    # Clear existing tags for this credential
    delete_db("DELETE FROM credential_tags WHERE sno = %s", (sno,))

    # Insert new tags
    for tag_name in tags_list:
        tag_name = tag_name.strip().lower()
        if tag_name:
            tag_id = get_tag_id(tag_name)
            if tag_id:
                insert_db("INSERT INTO credential_tags (sno, tag_id) VALUES (%s, %s)", (sno, tag_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_details', methods=['GET', 'POST'])
def add_details():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        description = request.form['description']
        tags_string = request.form['tags']
        
        salt = os.urandom(16)
        encrypted_pass = encrypt_pass(salt, password)

        params = (user_id, website, username, encrypted_pass, salt, description)
        query = """INSERT INTO ac_dtl_fernet (uid, site, username, password, pass_key, description) VALUES (%s, %s, %s, %s, %s, %s) """
        sno = insert_db(query, params)
        if sno is not None:
            if tags_string:
                tags_list = [tag.strip() for tag in tags_string.split(',') if tag.strip()]
                save_credential_tags(sno, tags_list)
            flash('Credential added successfully!', 'success')
        else:
            flash('Failed to add credential.', 'danger')
        return redirect(url_for('get_details'))
    
    return render_template('add_details.html')

@app.route('/get_details')
def get_details():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    search_query = request.args.get('search', '')
    tag_filter = request.args.get('tag', '')
    view_mode = request.args.get('view', 'grid') # grid or list

    # Fetch all unique tags for the current user for the filter dropdown
    tags_query = '''
        SELECT DISTINCT t.tag_name 
        FROM tags t
        JOIN credential_tags ct ON t.tag_id = ct.tag_id
        JOIN ac_dtl_fernet ac ON ct.sno = ac.sno
        WHERE ac.uid = %s
        ORDER BY t.tag_name
    '''
    all_tags = [row['tag_name'] for row in query_db(tags_query, (user_id,))]

    base_query = """SELECT ac.*, GROUP_CONCAT(DISTINCT t.tag_name ORDER BY t.tag_name) AS tags 
                  FROM ac_dtl_fernet ac 
                  LEFT JOIN credential_tags ct ON ac.sno = ct.sno 
                  LEFT JOIN tags t ON ct.tag_id = t.tag_id 
                  WHERE ac.uid = %s """
    query_args = [user_id]

    if search_query:
        base_query += " AND ac.site LIKE %s "
        query_args.append(f'%{search_query}%')
    
    if tag_filter:
        # Using a subquery to ensure we get credentials that HAVE the tag, even if they have others
        base_query += " AND EXISTS (SELECT 1 FROM credential_tags ct2 JOIN tags t2 ON ct2.tag_id = t2.tag_id WHERE ct2.sno = ac.sno AND t2.tag_name = %s) "
        query_args.append(tag_filter)

    base_query += " GROUP BY ac.sno ORDER BY ac.site"

    account_details = query_db(base_query, tuple(query_args))
    
    decrypted_details = []
    if account_details:
        for post in account_details:
            decrypted_post = post.copy()
            decrypted_post['password'] = decrypt_pass(post['pass_key'], post['password'])
            if decrypted_post['tags']:
                decrypted_post['tags'] = sorted(decrypted_post['tags'].split(','))
            else:
                decrypted_post['tags'] = []
            decrypted_details.append(decrypted_post)
            
    return render_template('get_details.html', 
                           posts=decrypted_details, 
                           search_query=search_query, 
                           all_tags=all_tags, 
                           tag_filter=tag_filter,
                           view_mode=view_mode)


@app.route('/edit_details/<int:sno>', methods=['GET', 'POST'])
def edit_details(sno):
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        description = request.form['description']
        tags_string = request.form['tags']

        salt = os.urandom(16)
        encrypted_pass = encrypt_pass(salt, password)

        query = """UPDATE ac_dtl_fernet SET site = %s, username = %s, password = %s, pass_key = %s, description = %s WHERE sno = %s AND uid = %s"""
        if update_db(query, (website, username, encrypted_pass, salt, description, sno, user_id)):
            if tags_string:
                tags_list = [tag.strip() for tag in tags_string.split(',') if tag.strip()]
                save_credential_tags(sno, tags_list)
            else:
                save_credential_tags(sno, []) # Clear all tags if input is empty
            flash('Credential updated successfully!', 'success')
        else:
            flash('Failed to update credential.', 'danger')
        return redirect(url_for('get_details'))

    entry = query_db("SELECT ac.*, GROUP_CONCAT(t.tag_name) AS tags FROM ac_dtl_fernet ac LEFT JOIN credential_tags ct ON ac.sno = ct.sno LEFT JOIN tags t ON ct.tag_id = t.tag_id WHERE ac.sno = %s AND ac.uid = %s GROUP BY ac.sno", (sno, user_id), one=True)
    if entry:
        entry['password'] = decrypt_pass(entry['pass_key'], entry['password'])
        if entry['tags']:
            entry['tags'] = entry['tags'].split(',')
        else:
            entry['tags'] = []
        return render_template('edit_details.html', entry=entry)
    
    flash('Credential not found.', 'warning')
    return redirect(url_for('get_details'))

@app.route('/delete_detail/<int:sno>', methods=['POST'])
def delete_detail(sno):
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))
    
    if delete_db("DELETE FROM ac_dtl_fernet WHERE sno = %s AND uid = %s", (sno, user_id)):
        flash('Credential deleted successfully!', 'success')
    else:
        flash('Failed to delete credential.', 'danger')
    return redirect(url_for('get_details'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('get_details'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        repassword = request.form['repassword']
        
        user_exists = query_db("SELECT * FROM user_details WHERE email_id = %s", (email,), one=True)
        
        if user_exists:
            flash("Email ID already registered!", 'warning')
            return render_template('register.html')
        
        if password != repassword:
            flash("Passwords didn't match!", 'danger')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        if insert_db("INSERT INTO user_details (email_id, password) VALUES (%s, %s)", (email, password_hash)):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('get_details'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = query_db("SELECT * FROM user_details WHERE email_id = %s", (email,), one=True)
        
        if user and check_password_hash(user['password'], password):
            if user['otp_enabled']:
                session['2fa_pending_user_id'] = user['u_id']
                return redirect(url_for('login_2fa'))
            else:
                session['username'] = user['email_id']
                flash('Logged in successfully!', 'success')
                return redirect(url_for('get_details'))
        else:
            flash('Incorrect username or password!', 'danger')

    return render_template('login.html')

@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    if 'username' in session:
        return redirect(url_for('get_details'))

    user_id = session.get('2fa_pending_user_id')
    if not user_id:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))

    user = query_db("SELECT email_id, otp_secret, otp_salt FROM user_details WHERE u_id = %s", (user_id,), one=True)
    if not user or not user['otp_secret'] or not user['otp_salt']:
        flash('2FA not configured for this account or an error occurred.', 'danger')
        session.pop('2fa_pending_user_id', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        totp_code = request.form['totp_code']
        
        salt_bytes = bytes.fromhex(user['otp_salt'])
        decrypted_otp_secret = decrypt_pass(salt_bytes, user['otp_secret'])
        
        if decrypted_otp_secret == "[DECRYPTION FAILED]":
            flash('Error decrypting 2FA secret. Please contact support.', 'danger')
            session.pop('2fa_pending_user_id', None)
            return redirect(url_for('login'))

        totp = pyotp.TOTP(decrypted_otp_secret)
        if totp.verify(totp_code, valid_window=1):
            session.pop('2fa_pending_user_id', None)
            session['username'] = user['email_id']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('get_details'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

    return render_template('login_2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    user = query_db("SELECT * FROM user_details WHERE u_id = %s", (user_id,), one=True)
    return render_template('profile.html', user=user)

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    user = query_db("SELECT email_id, otp_enabled FROM user_details WHERE u_id = %s", (user_id,), one=True)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('profile'))

    if user['otp_enabled']:
        flash('2FA is already enabled for your account.', 'info')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        totp_code = request.form['totp_code']
        temp_secret = session.get('2fa_temp_secret')

        if not temp_secret:
            flash('2FA setup session expired. Please try again.', 'danger')
            return redirect(url_for('profile'))

        totp = pyotp.TOTP(temp_secret)
        if totp.verify(totp_code):
            # Encrypt and save the secret
            otp_salt = os.urandom(16) # Generate a new salt for the OTP secret
            encrypted_otp_secret = encrypt_pass(otp_salt, temp_secret)
            otp_salt_hex = otp_salt.hex()

            update_query = "UPDATE user_details SET otp_secret = %s, otp_salt = %s, otp_enabled = TRUE WHERE u_id = %s"
            if update_db(update_query, (encrypted_otp_secret, otp_salt_hex, user_id)):
                session.pop('2fa_temp_secret', None)
                flash('2FA has been successfully enabled!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Failed to save 2FA settings. Please try again.', 'danger')
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

        # If verification fails or save fails, re-render the page with the same QR code
        provisioning_uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(user['email_id'], 'PasswordLocker')
        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_image = base64.b64encode(buf.getvalue()).decode('utf-8')
        return render_template('setup_2fa.html', qr_code_image=qr_code_image, secret_key=temp_secret)

    else: # GET request
        secret = pyotp.random_base32()
        session['2fa_temp_secret'] = secret
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(user['email_id'], 'PasswordLocker')

        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_image = base64.b64encode(buf.getvalue()).decode('utf-8')

        return render_template('setup_2fa.html', qr_code_image=qr_code_image, secret_key=secret)

@app.route('/disable_2fa', methods=['POST'])
def disable_2fa():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    user = query_db("SELECT email_id, password, otp_secret, otp_salt, otp_enabled FROM user_details WHERE u_id = %s", (user_id,), one=True)
    if not user or not user['otp_enabled']:
        flash('2FA is not enabled for your account or user not found.', 'danger')
        return redirect(url_for('profile'))

    submitted_password = request.form['password']
    submitted_totp_code = request.form['totp_code']

    # Verify user's password
    if not check_password_hash(user['password'], submitted_password):
        flash('Incorrect password.', 'danger')
        return redirect(url_for('profile'))

    # Verify TOTP code
    salt_bytes = bytes.fromhex(user['otp_salt'])
    decrypted_otp_secret = decrypt_pass(salt_bytes, user['otp_secret'])
    if decrypted_otp_secret == "[DECRYPTION FAILED]":
        flash('Error decrypting 2FA secret. Please contact support.', 'danger')
        return redirect(url_for('profile'))

    totp = pyotp.TOTP(decrypted_otp_secret)
    if not totp.verify(submitted_totp_code):
        flash('Invalid 2FA code.', 'danger')
        return redirect(url_for('profile'))

    # If both verifications pass, disable 2FA
    update_query = "UPDATE user_details SET otp_secret = NULL, otp_salt = NULL, otp_enabled = FALSE WHERE u_id = %s"
    if update_db(update_query, (user_id, )):
        flash('2FA has been successfully disabled.', 'success')
    else:
        flash('Failed to disable 2FA. Please try again.', 'danger')

    return redirect(url_for('profile'))

@app.route('/export_credentials')
def export_credentials():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    # Fetch all credentials for the user
    credentials = query_db("SELECT ac.*, GROUP_CONCAT(t.tag_name) AS tags FROM ac_dtl_fernet ac LEFT JOIN credential_tags ct ON ac.sno = ct.sno LEFT JOIN tags t ON ct.tag_id = t.tag_id WHERE ac.uid = %s GROUP BY ac.sno ORDER BY ac.site", (user_id,))

    # Prepare CSV data
    si = io.StringIO()
    cw = csv.writer(si)

    # CSV Header
    header = ['site', 'username', 'password', 'description', 'tags']
    cw.writerow(header)

    for cred in credentials:
        decrypted_password = decrypt_pass(cred['pass_key'], cred['password'])
        tags_str = ', '.join(cred['tags'].split(',')) if cred['tags'] else ''
        cw.writerow([cred['site'], cred['username'], decrypted_password, cred['description'], tags_str])

    output = si.getvalue()
    
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=password_locker_export.csv"
    return response

@app.route('/import_credentials', methods=['GET', 'POST'])
def import_credentials():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        csv_file = request.files['csv_file']
        if csv_file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if csv_file and csv_file.filename.endswith('.csv'):
            stream = io.StringIO(csv_file.stream.read().decode("UTF8"))
            csv_reader = csv.reader(stream)
            
            header = next(csv_reader) # Read header row
            expected_headers = ['site', 'username', 'password', 'description', 'tags']
            
            # Create a mapping from header name to its index
            header_map = {h.strip().lower(): i for i, h in enumerate(header)}

            # Check if all expected headers are present
            if not all(h in header_map for h in expected_headers):
                flash('Invalid CSV header. Expected: site, username, password, description, tags', 'danger')
                return redirect(request.url)

            success_count = 0
            fail_count = 0

            for row in csv_reader:
                try:
                    site = row[header_map['site']]
                    username = row[header_map['username']]
                    password = row[header_map['password']]
                    description = row[header_map['description']] if 'description' in header_map else ''
                    tags_string = row[header_map['tags']] if 'tags' in header_map else ''

                    salt = os.urandom(16)
                    encrypted_pass = encrypt_pass(salt, password)

                    params = (user_id, site, username, encrypted_pass, salt, description)
                    query = """INSERT INTO ac_dtl_fernet (uid, site, username, password, pass_key, description) VALUES (%s, %s, %s, %s, %s, %s) """
                    sno = insert_db(query, params)

                    if sno is not None:
                        if tags_string:
                            tags_list = [tag.strip() for tag in tags_string.split(',') if tag.strip()]
                            save_credential_tags(sno, tags_list)
                        success_count += 1
                    else:
                        fail_count += 1
                except Exception as e:
                    print(f"Error importing row: {row}, Error: {e}")
                    fail_count += 1
            
            flash(f'Import complete. Successfully imported {success_count} credentials, failed {fail_count}.', 'info')
            return redirect(url_for('get_details'))
        else:
            flash('Invalid file type. Please upload a CSV file.', 'danger')
            return redirect(request.url)

    return render_template('import_credentials.html')

@app.route('/password_audit')
def password_audit():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    credentials = query_db("SELECT sno, site, username, password, pass_key, created_at FROM ac_dtl_fernet WHERE uid = %s", (user_id,))

    audit_results = {
        'weak_passwords': [],
        'reused_passwords': {},
        'old_passwords': [],
        'total_credentials': len(credentials)
    }

    password_map = {}

    for cred in credentials:
        decrypted_password = decrypt_pass(cred['pass_key'], cred['password'])
        
        # Password Strength Check
        # zxcvbn scores: 0=terrible, 1=weak, 2=fair, 3=good, 4=strong
        strength_result = zxcvbn(decrypted_password)
        cred['strength_score'] = strength_result['score']
        cred['strength_feedback'] = strength_result['feedback'].get('warning', '') or ""
        if strength_result['score'] < 2: # Weak or terrible
            audit_results['weak_passwords'].append(cred)

        # Reused Password Check
        if decrypted_password not in password_map:
            password_map[decrypted_password] = []
        password_map[decrypted_password].append(cred)

        # Old Password Check (e.g., older than 1 year)
        if cred['created_at'] and (datetime.now() - cred['created_at']) > timedelta(days=365):
            audit_results['old_passwords'].append(cred)

    # Filter out passwords that are only used once for reused_passwords
    for password, cred_list in password_map.items():
        if len(cred_list) > 1:
            audit_results['reused_passwords'][password] = cred_list

    return render_template('password_audit.html', audit_results=audit_results)

if __name__ == "__main__":
    app.run(debug=True)