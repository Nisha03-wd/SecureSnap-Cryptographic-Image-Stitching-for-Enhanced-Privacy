from flask import Flask, request, jsonify, send_file
from io import BytesIO
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import zipfile
import json
import os

import requests
from dotenv import load_dotenv
from flask import session, redirect
from flask import Flask, render_template

load_dotenv()

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_SIGNUP_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
FIREBASE_SIGNIN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
FIREBASE_PASSWORD_RESET_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"

# Auth decorator
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

from flask import Flask, session, redirect, render_template_string

app = Flask(__name__)

# Set the secret key for session management
app.secret_key = 'rifat'  # You can generate a random key


# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ZIP_EXTENSIONS = {'zip'}
DEFAULT_BLOCK_SIZE = (100, 100)  # width, height in pixels

def allowed_file(filename, valid_exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in valid_exts

def derive_aes_key(key: str):
    if not key:
        raise ValueError("Please Input the key")
    if len(key) > 32:
        raise ValueError("The limit of key has been exceeded")
    return hashlib.sha256(key.encode()).digest()

def encrypt_data(key, data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt_data(key, data: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

def split_image_randomized_overlapping(image, block_size=DEFAULT_BLOCK_SIZE,
                                       overlap_ratio=0.2, random_offset_ratio=0.1):
    width, height = image.size
    block_width, block_height = block_size
    stride_x = int(block_width * (1 - overlap_ratio))
    stride_y = int(block_height * (1 - overlap_ratio))
    if stride_x <= 0 or stride_y <= 0:
        stride_x, stride_y = 1, 1

    blocks = []
    coords = []
    for x in range(0, width - block_width + 1, stride_x):
        for y in range(0, height - block_height + 1, stride_y):
            max_offset_x = int(block_width * random_offset_ratio)
            max_offset_y = int(block_height * random_offset_ratio)
            offset_x = random.randint(-max_offset_x, max_offset_x)
            offset_y = random.randint(-max_offset_y, max_offset_y)
            new_x = min(max(x + offset_x, 0), width - block_width)
            new_y = min(max(y + offset_y, 0), height - block_height)
            block = image.crop((new_x, new_y, new_x + block_width, new_y + block_height))
            blocks.append(block)
            coords.append((new_x, new_y))
    return blocks, coords, (width, height)

@app.route('/')
def index():
    if not session.get('user'):
        return redirect('/login')
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        payload = {
            "email": request.form['email'],
            "password": request.form['password'],
            "returnSecureToken": True
        }
        r = requests.post(FIREBASE_SIGNIN_URL, json=payload)
        if r.status_code == 200:
            data = r.json()
            session['user'] = {
                "email": data['email'],
                "idToken": data['idToken']
            }
            return redirect('/')
        else:
            return "Login failed: " + r.json().get('error', {}).get('message', 'Unknown error')

    return render_template('login.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        payload = {
            "email": request.form['email'],
            "password": request.form['password'],
            "returnSecureToken": True
        }
        r = requests.post(FIREBASE_SIGNUP_URL, json=payload)
        if r.status_code == 200:
            data = r.json()
            session['user'] = {
                "email": data['email'],
                "idToken": data['idToken']
            }
            return redirect('/')
        else:
            return render_template('signup.html', error="Signup failed: " + r.json().get('error', {}).get('message', 'Unknown error'))

    return render_template('signup.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email
        }
        r = requests.post(FIREBASE_PASSWORD_RESET_URL, json=payload)
        if r.status_code == 200:
            return "Password reset email sent to " + email
        else:
            return "Error: " + r.json().get('error', {}).get('message', 'Unknown error')
    return '''
       <form method="post" style="max-width: 400px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; border-radius: 10px; font-family: Arial, sans-serif; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
    <h2 style="text-align: center; color: #333;">Reset Password</h2>
    <label for="email" style="display: block; margin-bottom: 8px; font-weight: bold;">Enter your email:</label>
    <input type="email" name="email" id="email" required 
        style="width: 100%; padding: 10px; margin-bottom: 15px; border-radius: 5px; border: 1px solid #ccc;">
    
    <input type="submit" value="Send Reset Email" 
        style="width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">
    </form>

    '''


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')



# ---------------------------
# 1. Split Endpoint
# ---------------------------
@app.route('/split', methods=['POST'])
def split_image():
    if 'split-file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['split-file']
    if file.filename == '' or not allowed_file(file.filename, ALLOWED_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        image = Image.open(file)
    except Exception:
        return jsonify({'message': 'Unable to open image'}), 400

    blocks, coords, original_size = split_image_randomized_overlapping(
        image, block_size=DEFAULT_BLOCK_SIZE, overlap_ratio=0.2, random_offset_ratio=0.1
    )
    if not blocks:
        return jsonify({'message': 'Image too small to split'}), 400

    metadata = {
        "original_size": original_size,
        "block_size": list(DEFAULT_BLOCK_SIZE),
        "blocks": [{"block_index": i, "x": x, "y": y} for i, (x, y) in enumerate(coords)]
    }

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, block in enumerate(blocks):
            block_buffer = BytesIO()
            block.save(block_buffer, format="PNG")
            block_buffer.seek(0)
            zf.writestr(f"block_{i}.png", block_buffer.getvalue())
        zf.writestr("metadata.json", json.dumps(metadata))
    zip_buffer.seek(0)
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name="split_blocks.zip")

# ---------------------------
# 2. Encrypt ZIP Endpoint
# ---------------------------
@app.route('/encrypt_zip', methods=['POST'])
def encrypt_zip():
    if 'encrypt-zip-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'ZIP file and key are required'}), 400

    file = request.files['encrypt-zip-file']
    raw_key = request.form['key']
    try:
        key = derive_aes_key(raw_key)
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    if file.filename == '' or not allowed_file(file.filename, ZIP_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        input_zip = zipfile.ZipFile(BytesIO(file.read()))
    except Exception:
        return jsonify({'message': 'Unable to open ZIP file'}), 400

    encrypted_zip_buffer = BytesIO()
    with zipfile.ZipFile(encrypted_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zout:
        for info in input_zip.infolist():
            file_data = input_zip.read(info.filename)
            encrypted_file = encrypt_data(key, file_data)
            new_filename = info.filename.rsplit('.', 1)[0] + ".bin"
            zout.writestr(new_filename, encrypted_file)
    encrypted_zip_buffer.seek(0)
    return send_file(encrypted_zip_buffer, mimetype='application/zip', as_attachment=True, download_name="encrypted_blocks.zip")

# ---------------------------
# 3. Stitch & Decrypt Endpoint
# ---------------------------
@app.route('/stitch_decrypt', methods=['POST'])
def stitch_decrypt():
    if 'stitch-zip-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'Encrypted ZIP and key are required'}), 400

    file = request.files['stitch-zip-file']
    raw_key = request.form['key']
    try:
        key = derive_aes_key(raw_key)
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    if file.filename == '' or not allowed_file(file.filename, ZIP_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        encrypted_zip = zipfile.ZipFile(BytesIO(file.read()))
    except Exception:
        return jsonify({'message': 'Unable to open encrypted ZIP file'}), 400

    metadata = None
    blocks_dict = {}
    for info in encrypted_zip.infolist():
        fname = info.filename
        encrypted_data = encrypted_zip.read(fname)
        try:
            decrypted_data = decrypt_data(key, encrypted_data)
        except Exception:
            return jsonify({'message': f'Error decrypting {fname}'}), 400

        if "metadata" in fname.lower():
            try:
                metadata = json.loads(decrypted_data.decode())
            except Exception:
                return jsonify({'message': 'Error reading metadata'}), 400
        else:
            try:
                block_img = Image.open(BytesIO(decrypted_data))
                idx = int(fname.split('_')[-1].split('.')[0])
                blocks_dict[idx] = block_img
            except Exception:
                continue

    if metadata is None:
        return jsonify({'message': 'Missing metadata for stitching'}), 400

    orig_width, orig_height = metadata.get("original_size", (0, 0))
    if orig_width == 0 or orig_height == 0:
        return jsonify({'message': 'Invalid original image size in metadata'}), 400

    stitched_image = Image.new("RGB", (orig_width, orig_height))
    for block_info in metadata["blocks"]:
        idx = block_info["block_index"]
        x = block_info["x"]
        y = block_info["y"]
        block_img = blocks_dict.get(idx)
        if block_img:
            stitched_image.paste(block_img, (x, y))
    out_buffer = BytesIO()
    stitched_image.save(out_buffer, format="PNG")
    out_buffer.seek(0)
    return send_file(out_buffer, mimetype='image/png', as_attachment=True, download_name="stitched_image.png")

# ---------------------------
# 4. Forgot Key Endpoint (Simulated)
# ---------------------------
@app.route('/forgot_key', methods=['POST'])
def forgot_key():
    email = request.form.get("email")
    if not email:
        return jsonify({'message': 'Please provide your email address'}), 400
    return jsonify({'message': f'An authentication email has been sent to {email}.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
