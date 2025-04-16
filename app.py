import logging
import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from config.config import Config  # Import configuration class

# Initialize the Flask app
app = Flask(__name__)
app.config.from_object(Config)  # Load configuration from the Config class

# Logging configuration
logging.basicConfig(level=logging.DEBUG, filename='logs/app.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

mail = Mail(app)
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Contact form submission model
class ContactSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Home page
@app.route('/')
def home():
    current_year = datetime.now().year
    logger.debug(f"Rendering home page; current year: {current_year}")
    return render_template('index.html', current_year=current_year)

# Dashboard page (requires login)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in first', 'warning')
        logger.warning("Dashboard access attempted without login.")
        return redirect(url_for('login'))
    
    current_year = datetime.now().year
    username = session['username']
    user = User.query.filter_by(username=username).first()
    logger.debug(f"User {username} accessed dashboard; user_info: {user}")
    
    return render_template('dashboard.html', username=username, user_info=user, current_year=current_year)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            logger.error("Login failed: Missing fields.")
            return redirect(url_for('login'))
            
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            logger.info(f"User {username} logged in successfully.")
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
            logger.warning(f"Invalid login attempt for user {username}.")
    
    return render_template('login.html')

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields', 'danger')
            logger.error("Registration failed: Missing fields.")
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            logger.error("Registration failed: Password mismatch.")
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            logger.warning(f"Registration failed: Username {username} already exists.")
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        logger.info(f"New user registered: {username}")
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Logout route
@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        session.pop('username', None)
        flash(f'You have been logged out, {username}', 'info')
        logger.info(f"User {username} logged out.")
    return redirect(url_for('home'))

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_code = str(random.randint(100000, 999999))  # Generate a 6-digit code
            session['reset_code'] = reset_code
            session['reset_email'] = email

            try:
                msg = Message("Password Reset Code", recipients=[email])
                msg.body = f"Your password reset code is: {reset_code}"
                mail.send(msg)
                flash('A reset code has been sent to your email.', 'info')
                logger.info(f"Password reset code sent to {email}. Code: {reset_code}")
                return redirect(url_for('verify_reset_code'))  # Redirect to verify code page
            except Exception as e:
                flash('Error sending email. Please try again later.', 'danger')
                logger.error(f"Error sending email to {email}: {e}")
        else:
            flash('No account is associated with that email.', 'warning')
            logger.warning(f"Password reset requested for unknown email: {email}")
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Verify Reset Code Route
@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    if 'reset_code' not in session or 'reset_email' not in session:
        flash('No reset code found. Please request a password reset first.', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        entered_code = request.form.get('reset_code')
        if entered_code == session.get('reset_code'):
            flash('Reset code verified. You can now reset your password.', 'success')
            return redirect(url_for('reset_password'))  # Redirect to the reset password page
        else:
            flash('Incorrect reset code. Please try again.', 'danger')
            return redirect(url_for('verify_reset_code'))
    
    return render_template('verify_reset_code.html')

# Reset Password Route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_code' not in session or 'reset_email' not in session:
        flash('No reset code found. Please request a password reset first.', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if not all([new_password, confirm_new_password]):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('reset_password'))
        
        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))

        reset_email = session.get('reset_email')
        user = User.query.filter_by(email=reset_email).first()

        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been reset successfully.', 'success')
            session.pop('reset_code', None)  # Remove reset code after successful reset
            session.pop('reset_email', None)  # Remove reset email after successful reset
            logger.info(f"Password reset successfully for user {user.username}")
            return redirect(url_for('login'))
        else:
            flash('User not found. Please request a password reset again.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('Please log in to change your password.', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# Contact Us route
@app.route('/contact_us', methods=['POST'])
def contact_us():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    
    submission = ContactSubmission(name=name, email=email, message=message)
    db.session.add(submission)
    db.session.commit()
    
    logger.debug(f"Received contact submission: {submission}")
    flash('Your message has been sent successfully!', 'success')
    return redirect(url_for('dashboard'))

# View Contact Submissions (Only for admins)
@app.route('/contact_submissions')
def view_contact_submissions():
    if 'username' not in session:
        flash('Please log in to view contact submissions', 'warning')
        return redirect(url_for('login'))
    if session['username'] not in ['admin', 'Bad']:
        flash('Access denied: You do not have permission to view submitted contact forms.', 'danger')
        return redirect(url_for('dashboard'))
    
    submissions = ContactSubmission.query.all()
    logger.debug(f"Displaying all contact submissions: {submissions}")
    return render_template('contact_submissions.html', submissions=submissions)

if __name__ == '__main__':
    # Ensure the app context is set before running, and create tables if not already created
    with app.app_context():
        db.create_all()  # Ensure tables are created before running the app
    
    try:
        logger.info("Starting Flask app on host: 192.168.18.4, port: 5000")
        app.run(host='0.0.0.0', port=5000)
    except Exception as e:
        logger.error(f"Error starting app: {e}")
