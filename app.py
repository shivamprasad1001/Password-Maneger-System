from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_mysqldb import MySQL
from Crypto.Cipher import AES
import base64
import os
import pandas as pd  # For exporting to Excel

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Required for session storage

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '' # Enter your password here
app.config['MYSQL_DB'] = 'password_manager'

mysql = MySQL(app)

SECRET_KEY = b'16ByteSecretKey!'

# AES Encryption & Decryption
def encrypt_password(password):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_password(encrypted_password):
    try:
        encrypted_password = base64.b64decode(encrypted_password)
        nonce = encrypted_password[:16]
        ciphertext = encrypted_password[16:]
        cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext).decode('utf-8')
    except:
        return "Decryption Error"

# Home Page: List all passwords
@app.route('/')
def index():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM passwords")
    passwords = cur.fetchall()
    cur.close()
    decrypted_passwords = [
        (p[0], p[1], p[2], decrypt_password(p[3])) for p in passwords
    ]
    return render_template('index.html', passwords=decrypted_passwords)

# Add New Password
@app.route('/add', methods=['POST'])
def add_password():
    salt  =  request.form.get('salt')
    username = request.form['username']
    password = encrypt_password(request.form['password'])  # Encrypt before saving

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO passwords (salt , username, password_hash) VALUES (%s, %s, %s)",
                (salt , username, password))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('index'))

# Copy Text Route (Stores in session)
@app.route('/copy_text', methods=['POST'])
def copy_text():
    text_to_copy = request.form['text_to_copy']
    session['copied_text'] = text_to_copy  # Store in session
    return redirect(url_for('index'))

# Edit Password Page
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        new_username = request.form['username']
        new_password = encrypt_password(request.form['password'])  # Encrypt new password
        cur.execute("UPDATE passwords SET username=%s, password_hash=%s WHERE id=%s",
                    (new_username, new_password, id))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('index'))

    cur.execute("SELECT id, salt , username, password_hash FROM passwords WHERE id=%s", (id,))
    entry = cur.fetchone()
    cur.close()

    if entry:
        return render_template('edit.html', entry=(entry[0], entry[1], entry[2], decrypt_password(entry[3])))
    else:
        return "Entry not found", 404

# Delete Password
@app.route('/delete/<int:id>')
def delete_password(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM passwords WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('index'))

# Export Passwords to Excel
@app.route('/export')
def export_to_excel():
    cur = mysql.connection.cursor()
    cur.execute("SELECT salt , username, password_hash FROM passwords")
    data = cur.fetchall()
    cur.close()

    # Convert to DataFrame
    df = pd.DataFrame(data, columns=['Website/App', 'Username', 'Encrypted Password'])
    
    # Save as Excel File
    file_path = "password_backup.xlsx"
    df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
