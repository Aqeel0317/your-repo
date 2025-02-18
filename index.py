from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from functools import wraps
from datetime import datetime, timedelta
import os
import time
import jwt
import json
import requests
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import base64

# Initialize Flask App
app = Flask(__name__)
import os


with open('config.json') as config_file:
    config_data = json.load(config_file)

# Update configuration with environment variables if they exist
for key, value in config_data.items():
    app.config[key] = os.environ.get(key, value)

# Optionally load from environment variables; if not found, generate random values.


# If Railway provides DATABASE_URL, use it instead of the SQLite URI.
if os.environ.get('DATABASE_URL'):
    database_url = os.environ['DATABASE_URL']
    # Railway may use the prefix "postgres://", but SQLAlchemy requires "postgresql://"
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url


# Used for generating reset tokens

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Serializer for generating tokens (e.g., password resets)
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except (SignatureExpired, BadSignature):
        return None
    return email

# User Model with roles: admin, psychologist, approved, patient
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')  # Options: 'admin', 'psychologist', 'approved', 'patient'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Additional Models
class PatientProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(150), nullable=False)
    contact_number = db.Column(db.String(20))
    address = db.Column(db.String(255))
    trauma_details = db.Column(db.Text)
    user = db.relationship('User', backref=db.backref('profile', uselist=False))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    appointment_datetime = db.Column(db.DateTime, nullable=False)
    zoom_link = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='scheduled')

    patient = db.relationship(
        'User',
        foreign_keys=[patient_id],
        backref=db.backref('appointments_as_patient', cascade="all, delete-orphan", passive_deletes=True)
    )
    psychologist = db.relationship(
        'User',
        foreign_keys=[psychologist_id],
        backref=db.backref('appointments_as_psychologist', cascade="all, delete-orphan", passive_deletes=True)
    )

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

# New Model: TherapySignUp for capturing therapy service sign-ups
class TherapySignUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    intake_notes = db.Column(db.Text, default="")
    assigned_volunteer = db.Column(db.String(100), default="")
    first_session_date = db.Column(db.Date, nullable=True)
    first_session_time = db.Column(db.Time, nullable=True)

# Decorator for Admin-only Routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Decorator for routes accessible by admin and approved users
def privileged_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'approved']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def get_zoom_access_token():
    client_id = app.config['ZOOM_CLIENT_ID']
    client_secret = app.config['ZOOM_CLIENT_SECRET']
    account_id = app.config['ZOOM_ACCOUNT_ID']
    
    if not client_id or not client_secret or not account_id:
        print("Zoom Server-to-Server OAuth credentials are not configured.")
        return None
    
    # Prepare Basic Auth header using client_id and client_secret
    auth_str = f"{client_id}:{client_secret}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    # Zoom token endpoint with account_id in the query string
    token_url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={account_id}"
    
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(token_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data['access_token']
    else:
        print("Error retrieving Zoom access token:", response.json())
        return None


# Dummy function to simulate Zoom meeting creation
def create_zoom_meeting(topic="Appointment", start_time=None, duration=30):
    token = get_zoom_access_token()
    if not token:
        print("Failed to obtain Zoom access token.")
        return None

    if not start_time:
        start_time = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + 'Z'
    
    meeting_details = {
        "topic": topic,
        "type": 2,  # Scheduled meeting
        "start_time": start_time,
        "duration": duration,
        "timezone": "UTC",
        "agenda": "Psychological Appointment",
        "settings": {
            "host_video": False,
            "participant_video": False,
            "join_before_host": True,
            "mute_upon_entry": True
        }
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(
        "https://api.zoom.us/v2/users/me/meetings",
        headers=headers,
        json=meeting_details
    )
    
    if response.status_code == 201:
        meeting_info = response.json()
        return meeting_info.get('join_url')
    else:
        print("Error creating Zoom meeting:", response.json())
        return None


import hmac
import hashlib
import base64

def generate_zoom_signature(meeting_number, role):
    """
    Generates a signature required by the Zoom Web SDK using your server-to-server credentials.
    :param meeting_number: The Zoom meeting number (as a string).
    :param role: 0 for attendee, 1 for host.
    :return: A signature string.
    """
    # Use your client credentials instead of separate API key/secret.
    client_id = app.config['ZOOM_CLIENT_ID']
    client_secret = app.config['ZOOM_CLIENT_SECRET']
    ts = int(round(time.time() * 1000)) - 30000
    msg = f'{client_id}{meeting_number}{ts}{role}'
    message = base64.b64encode(msg.encode())
    hash_val = hmac.new(client_secret.encode(), message, hashlib.sha256).digest()
    hash_base64 = base64.b64encode(hash_val).decode()
    signature = f'{client_id}.{meeting_number}.{ts}.{role}.{hash_base64}'
    # Base64 encode the entire signature and strip any trailing "="
    signature_encoded = base64.b64encode(signature.encode()).decode().rstrip("=")
    return signature_encoded


# --------------------------
# Routes
# --------------------------

# Home Page
@app.route('/')
def home():
    # Ensure your index.html includes: About Us, Why?, Sign Up Here!, The Team, Contact Us
    return render_template('index.html')

# Therapy Service Sign Up Page (updated to act as the registration route)
@app.route('/therapy_signup', methods=['GET', 'POST'])
def therapy_signup():
    if request.method == 'POST':
        # Get form data from the sign-up form
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        gender = request.form.get('gender')
        dob_str = request.form.get('date_of_birth')  # Expecting YYYY-MM-DD format
        try:
            date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return redirect(url_for('therapy_signup'))
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        reason = request.form.get('reason')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate password fields
        if not password or password != confirm_password:
            flash("Passwords do not match or are missing.", "danger")
            return redirect(url_for('therapy_signup'))
        
        # Check if email is already registered
        if User.query.filter_by(email=email).first():
            flash("Email is already registered. Please log in.", "warning")
            return redirect(url_for('login'))
        
        # Create a new user account
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, role='patient')
        db.session.add(user)
        db.session.commit()
        
        # Create a patient profile (using first and last name, and phone number)
        full_name = f"{first_name} {last_name}"
        profile = PatientProfile(user_id=user.id,
                                 full_name=full_name,
                                 contact_number=phone_number,
                                 address='',
                                 trauma_details='')
        db.session.add(profile)
        db.session.commit()
        
        # Optionally, also store the therapy sign-up details in the TherapySignUp table
        signup = TherapySignUp(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            email=email,
            phone_number=phone_number,
            reason=reason
        )
        db.session.add(signup)
        db.session.commit()
        
        # Send email confirmation for sign up
        try:
            msg = Message('Therapy Service Sign Up Confirmation',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f"""Thank you for signing up for our therapy services, a representative will connect with you soon!
            
Here are your responses:
First Name: {first_name}
Last Name: {last_name}
Gender: {gender}
Date of Birth: {date_of_birth}
Email: {email}
Phone Number: {phone_number}
Reason for seeking therapy: {reason}
            """
            mail.send(msg)
        except Exception as e:
            print("Error sending sign-up confirmation email:", e)
        
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    return render_template('therapy_signup.html')

# (The /register route is now removed.)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')
from urllib.parse import urlparse, parse_qs

@app.route('/zoom_meeting/<int:appointment_id>')
@login_required
def zoom_meeting(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    # Only allow the patient or assigned psychologist to join the meeting
    if current_user.id not in [appointment.patient_id, appointment.psychologist_id]:
        abort(403)
    
    # Extract meeting number and password from the Zoom join URL.
    # (Assumes a join URL of the form: "https://zoom.us/j/123456789?pwd=abc")
    parsed_url = urlparse(appointment.zoom_link)
    path_parts = parsed_url.path.split('/')
    meeting_number = None
    for i, part in enumerate(path_parts):
        if part == 'j' and i + 1 < len(path_parts):
            meeting_number = path_parts[i + 1]
            break
    query_params = parse_qs(parsed_url.query)
    meeting_password = query_params.get('pwd', [None])[0]

    if not meeting_number:
        flash("Invalid Zoom meeting link.", "danger")
        return redirect(url_for('dashboard'))

    # Generate a signature for the meeting using your client credentials.
    # (role=0 for attendee; use role=1 if host privileges are needed)
    signature = generate_zoom_signature(meeting_number, 0)

    return render_template('zoom_meeting.html',
                           client_id=app.config['ZOOM_CLIENT_ID'],
                           meeting_number=meeting_number,
                           meeting_password=meeting_password,
                           signature=signature)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                msg = Message('Password Reset Request',
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[email])
                msg.body = f"""Hello,

To reset your password, click the following link:
{reset_url}

If you did not request a password reset, please ignore this email.
"""
                mail.send(msg)
                flash("An email has been sent with instructions to reset your password.", "info")
            except Exception as e:
                print(e)
                flash("Failed to send reset email. Please try again later.", "danger")
        else:
            flash("If an account with that email exists, a reset email has been sent.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        new_password = request.form['password']
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash("Your password has been updated!", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if current_user.role != 'patient':
        flash("Only patients can have profiles.", "warning")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        full_name = request.form['full_name']
        contact_number = request.form['contact_number']
        address = request.form['address']
        trauma_details = request.form['trauma_details']
        if current_user.profile:
            current_user.profile.full_name = full_name
            current_user.profile.contact_number = contact_number
            current_user.profile.address = address
            current_user.profile.trauma_details = trauma_details
        else:
            profile = PatientProfile(user_id=current_user.id,
                                     full_name=full_name,
                                     contact_number=contact_number,
                                     address=address,
                                     trauma_details=trauma_details)
            db.session.add(profile)
        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('dashboard'))
    return render_template('profile.html', profile=current_user.profile)

@app.route('/appointments')
@login_required
def appointments():
    if current_user.role == 'patient':
        appts = Appointment.query.filter_by(patient_id=current_user.id).all()
    elif current_user.role in ['psychologist', 'approved', 'admin']:
        appts = Appointment.query.filter_by(psychologist_id=current_user.id).all()
    else:
        appts = []
    return render_template('appointments.html', appointments=appts)

@app.route('/admin')
@login_required
@privileged_required
def admin_dashboard():
    patients = User.query.filter_by(role='patient').all()
    psychologists = User.query.filter_by(role='psychologist').all()
    return render_template('admin_dashboard.html', patients=patients, psychologists=psychologists)

@app.route('/assign/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@privileged_required
def assign_patient(patient_id):
    patient = User.query.get_or_404(patient_id)
    psychologists = User.query.filter_by(role='psychologist').all()
    if request.method == 'POST':
        psychologist_id = request.form['psychologist_id']
        appointment_time_str = request.form['appointment_datetime']
        try:
            appointment_datetime = datetime.strptime(appointment_time_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date/time format. Use YYYY-MM-DDTHH:MM', 'danger')
            return redirect(url_for('assign_patient', patient_id=patient_id))
        
        zoom_link = create_zoom_meeting(topic="Psychological Appointment", 
                                        start_time=appointment_datetime.isoformat() + 'Z')
        if not zoom_link:
            flash("Failed to create Zoom meeting. Please try again.", "danger")
            return redirect(url_for('assign_patient', patient_id=patient_id))
        
        appointment = Appointment(
            patient_id=patient.id,
            psychologist_id=psychologist_id,
            appointment_datetime=appointment_datetime,
            zoom_link=zoom_link
        )
        db.session.add(appointment)
        db.session.commit()
        
        psychologist = User.query.get(psychologist_id)
        
        try:
            # Updated email confirmation for session booking
            patient_msg = Message('Session Booking Confirmation',
                                  sender=app.config['MAIL_USERNAME'],
                                  recipients=[patient.email])
            meeting_url = url_for('zoom_meeting', appointment_id=appointment.id, _external=True)
            patient_msg.body = f"""Thank you for booking a session with {psychologist.email}.
Your appointment is scheduled on {appointment_datetime.strftime('%Y-%m-%d')} at {appointment_datetime.strftime('%H:%M')}.

Please click the link below to join your session on our website:
{meeting_url}

We look forward to seeing you!
"""
            mail.send(patient_msg)
        except Exception as e:
            print("Error sending email to patient:", e)
            flash('Appointment created, but failed to send email to patient.', 'warning')
        
        try:
            psych_msg = Message('New Appointment Assigned',
                                sender=app.config['MAIL_USERNAME'],
                                recipients=[psychologist.email])
            psych_msg.body = f"""Hello,

A new appointment has been scheduled for you.
Date/Time: {appointment_datetime}
Join the meeting using this link: {meeting_url}

Best regards,
The Team
"""
            mail.send(psych_msg)
        except Exception as e:
            print("Error sending email to psychologist:", e)
            flash('Appointment created, but failed to send email to psychologist.', 'warning')
        
        flash('Appointment created and emails sent successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('assign_patient.html', patient=patient, psychologists=psychologists)

@app.route('/admin/add_approved_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_approved_user():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(email=email, password=password, role='approved')
        db.session.add(user)
        db.session.commit()
        flash("Approved user created successfully", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('add_approved_user.html')
@app.route('/admin/therapysignups/<int:signup_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_therapysignup(signup_id):
    signup = TherapySignUp.query.get_or_404(signup_id)
    try:
        db.session.delete(signup)
        db.session.commit()
        flash("Therapy sign-up deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting therapy sign-up: {e}", "danger")
    return redirect(url_for('admin_therapysignups'))

@app.route('/admin/add_psychologist', methods=['GET', 'POST'])
@login_required
@admin_required
def add_psychologist():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(email=email, password=password, role='psychologist')
        db.session.add(user)
        db.session.commit()
        flash("Psychologist added successfully", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('add_psychologist.html')

# New Admin Routes for Therapy Sign-Ups
from urllib.parse import urlparse, parse_qs

# Route to display all scheduled meetings (for admin and verified users)
@app.route('/scheduled_meetings')
@login_required
@privileged_required
def scheduled_meetings():
    # Retrieve all appointments; you can also apply filtering or sorting as needed.
    appointments = Appointment.query.order_by(Appointment.appointment_datetime).all()
    return render_template('scheduled_meetings.html', appointments=appointments)


# Route to join a meeting as an admin/verified user.
@app.route('/admin_zoom_meeting/<int:appointment_id>')
@login_required
@privileged_required
def admin_zoom_meeting(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    # For admin/verified users, we allow joining any meeting.
    # Extract the meeting number and password from the Zoom join URL.
    # (Assumes a join URL of the form: "https://zoom.us/j/123456789?pwd=abc")
    parsed_url = urlparse(appointment.zoom_link)
    path_parts = parsed_url.path.split('/')
    meeting_number = None
    for i, part in enumerate(path_parts):
        if part == 'j' and i + 1 < len(path_parts):
            meeting_number = path_parts[i + 1]
            break
    query_params = parse_qs(parsed_url.query)
    meeting_password = query_params.get('pwd', [None])[0]

    if not meeting_number:
        flash("Invalid Zoom meeting link.", "danger")
        return redirect(url_for('scheduled_meetings'))

    # Generate a signature for the meeting using your client credentials.
    # (role=0 for attendee; change to 1 if you need host privileges)
    signature = generate_zoom_signature(meeting_number, 0)

    return render_template('admin_zoom_meeting.html',
                           client_id=app.config['ZOOM_CLIENT_ID'],
                           meeting_number=meeting_number,
                           meeting_password=meeting_password,
                           signature=signature)

@app.route('/admin/therapysignups')
@login_required
@admin_required
def admin_therapysignups():
    signups = TherapySignUp.query.all()
    return render_template('admin_therapysignups.html', signups=signups)

@app.route('/admin/therapysignups/<int:signup_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_therapysignup_detail(signup_id):
    signup = TherapySignUp.query.get_or_404(signup_id)
    if request.method == 'POST':
        signup.intake_notes = request.form.get('intake_notes', '')
        signup.assigned_volunteer = request.form.get('assigned_volunteer', '')
        first_session_date_str = request.form.get('first_session_date', '')
        first_session_time_str = request.form.get('first_session_time', '')
        if first_session_date_str:
            try:
                signup.first_session_date = datetime.strptime(first_session_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Invalid date format for First Session Date. Use YYYY-MM-DD.", "danger")
                return redirect(url_for('admin_therapysignup_detail', signup_id=signup_id))
        if first_session_time_str:
            try:
                signup.first_session_time = datetime.strptime(first_session_time_str, '%H:%M').time()
            except ValueError:
                flash("Invalid time format for First Session Time. Use HH:MM in 24-hour format.", "danger")
                return redirect(url_for('admin_therapysignup_detail', signup_id=signup_id))
        db.session.commit()
        flash("Therapy sign-up details updated.", "success")
        return redirect(url_for('admin_therapysignups'))
    return render_template('admin_therapysignup_detail.html', signup=signup, current_year=datetime.utcnow().year)

# --------------------------
# New Route: Delete User (Admin Only)
# --------------------------
# --------------------------
# Modified Delete User Route (Admin Only)
# --------------------------
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Prevent deletion of admin accounts
    if user.role == 'admin':
        flash("Admin users cannot be deleted.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Removed the check for associated appointments so that admin can delete the user.
    # Delete the user profile if it exists.
    if user.profile:
        db.session.delete(user.profile)
    # Deleting the user will cascade delete associated appointments due to the cascade settings.
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully", "success")
    return redirect(url_for('admin_dashboard'))

# --------------------------
# New Route: Delete Meeting (Admin Only)
# --------------------------
@app.route('/admin/delete_meeting/<int:appointment_id>', methods=['POST'])
@login_required
@admin_required
def delete_meeting(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    db.session.delete(appointment)
    db.session.commit()
    flash("Meeting deleted successfully", "success")
    return redirect(url_for('scheduled_meetings'))

# --------------------------
# Run the App
# --------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create a default admin account if none exists
        if not User.query.filter_by(role='admin').first():
            default_admin_email = app.config.get('DEFAULT_ADMIN_EMAIL')
            default_admin_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
            
            admin_user = User(
                email=default_admin_email,
                password=bcrypt.generate_password_hash(default_admin_password).decode('utf-8'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print(f'Default admin created: email: {default_admin_email} / password: {default_admin_password}')
    app.run(debug=True)
