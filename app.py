# app.py
from flask import Flask, render_template, redirect, url_for, session, flash, request, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_mail import *
import random
import os
import datetime
import sqlite3
from werkzeug.utils import secure_filename
from yolo_model import run_yolo_analysis
import ast
import smtplib
from email.message import EmailMessage
from PIL import Image

app = Flask(__name__)

# SQLite Config
DATABASE = 'database.db'
app.secret_key = 'secret_key'

# Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'prasuryakakati97072@gmail.com'
app.config['MAIL_PASSWORD'] = 'pauezqqroblohybg'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class EmailVerifyForm(FlaskForm):
    otp = StringField("Enter OTP", validators=[DataRequired()])
    submit = SubmitField("Verify")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        session['email'] = email
        hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user:
            flash("Email already registered. Please log in or use a different email.")
            conn.close()
            return redirect(url_for('register'))
        else:
            conn.execute("INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, ?)",
                         (name, email, hash_password.decode('utf-8'), False))
            conn.commit()
            conn.close()

        otp = random.randint(100000, 999999)
        session['otp'] = otp
        msg = Message('Email Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Hi {name},\nYour email OTP is: {otp}"
        mail.send(msg)

        return render_template('email_verify.html', email=email, form=EmailVerifyForm())

    return render_template('register.html', form=form)

@app.route('/email_verify', methods=['GET', 'POST'])
def email_verify():
    form = EmailVerifyForm()
    if form.validate_on_submit():
        user_otp = form.otp.data
        email = session.get('email')
        if 'otp' in session and int(user_otp) == session['otp']:
            flash("Email verified successfully!", "success")
            conn = get_db_connection()
            conn.execute("UPDATE users SET verified = 1 WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            conn = get_db_connection()
            conn.execute("DELETE FROM users WHERE email = ? AND verified = 0", (email,))
            conn.commit()
            conn.close()
            return redirect(url_for('register'))

    return render_template('email_verify.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()

        if user:
            annotated_img = session.pop('annotated_img', None)
            detections = session.pop('detections', None)
            return render_template('dashboard.html', user=user, annotated_img=annotated_img, detections=detections)

    return redirect(url_for('login'))

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'img' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))

    file = request.files['img']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_folder = os.path.join('static/uploads', str(session['user_id']))
        os.makedirs(user_folder, exist_ok=True)
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)

        result_img_path, detections = run_yolo_analysis(filepath)

        conn = get_db_connection()

        # Count existing reports for this user
        report_count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE user_id = ?", (session['user_id'],)
        ).fetchone()[0] + 1

        # Generate application number
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        application_number = f"APP-{timestamp}-{session['user_id']}-{report_count}"

        conn.execute("""
            INSERT INTO reports (user_id, application_number, image_path, detection_result, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session['user_id'],
            application_number,
            result_img_path,
            str(detections),
            datetime.datetime.now()
        ))
        conn.commit()
        conn.close()

        session['annotated_img'] = result_img_path
        session['detections'] = detections

        return redirect(url_for('dashboard'))

    flash('File type not allowed')
    return redirect(url_for('dashboard'))


@app.route('/reports')
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    report_data = conn.execute(
        "SELECT id, application_number, image_path, detection_result, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()

    parsed_reports = []
    for report in report_data:
        r = dict(report)
        try:
            r['parsed_detections'] = ast.literal_eval(r['detection_result']) if r['detection_result'] else []
        except Exception:
            r['parsed_detections'] = []
        parsed_reports.append(r)

    return render_template('reports.html', reports=parsed_reports)

@app.route('/send_report', methods=['POST'])
def send_report():
    application_number = request.form.get('application_number')
    email = request.form.get('email')

    if not application_number or not email:
        flash("Application number and email are required", "danger")
        return redirect(url_for('index'))

    conn = get_db_connection()
    report = conn.execute(
        "SELECT image_path, detection_result FROM reports WHERE application_number = ?", (application_number,)
    ).fetchone()
    conn.close()

    if not report:
        flash("No report found for the provided application number.", "warning")
        return redirect(url_for('index'))

    image_path = report['image_path']
    detection_result = ast.literal_eval(report['detection_result']) if report['detection_result'] else []

    # Check image validity using Pillow
    try:
        with Image.open(image_path) as img:
            img_format = img.format
    except Exception:
        flash("Image file is invalid or missing.", "danger")
        return redirect(url_for('index'))

    # Build detection result string
    if detection_result:
        detection_text = "\n".join([f"{d['label']} — Confidence: {d['confidence']}%" for d in detection_result])
    else:
        detection_text = "No findings detected in the X-ray."

    # Compose email
    msg = Message(
        subject="🦷 Your Dental X-ray Analysis Report",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f"Dear User,\n\nHere is your dental report for Application No: {application_number}.\n\nFindings:\n{detection_text}\n\nRegards,\nDibrugarh Dental College"

    # Attach image
    with open(image_path, 'rb') as img_file:
        msg.attach(
            filename=os.path.basename(image_path),
            content_type=f'image/{img_format.lower()}',
            data=img_file.read()
        )

    try:
        mail.send(msg)
        flash("Report has been sent to your email.", "success")
    except Exception as e:
        print("[ERROR] Email send failed:", e)
        flash("Failed to send email. Please try again later.", "danger")

    
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
