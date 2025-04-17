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

# ✅ Make datetime available in all templates
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Home page
@app.route('/')
def home():
    current_year = datetime.now().year
    logger.debug(f"Rendering home page; current year: {current_year}")
    
    # Show username after login
    if 'username' in session:
        username = session['username']
        return render_template('index.html', current_year=current_year, username=username)
    
    return render_template('index.html', current_year=current_year)

# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = User.query.filter_by(username=username).first()
    return render_template('dashboard.html', username=username, user_info=user)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))  # Redirect to home page after login
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash(f'You have been logged out', 'info')
    return redirect(url_for('home'))  # Redirect to home after logout

# Forgot Password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_code = str(random.randint(100000, 999999))
            session['reset_code'] = reset_code
            session['reset_email'] = email

            try:
                msg = Message("Password Reset Code", recipients=[email])
                msg.body = f"Your password reset code is: {reset_code}"
                mail.send(msg)
                flash('A reset code has been sent to your email.', 'info')
                return redirect(url_for('verify_reset_code'))
            except Exception as e:
                flash('Error sending email. Please try again later.', 'danger')
        else:
            flash('No account is associated with that email.', 'warning')
    
    return render_template('forgot_password.html')

# Verify Reset Code
@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    if 'reset_code' not in session or 'reset_email' not in session:
        flash('No reset code found.', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        entered_code = request.form.get('reset_code')
        if entered_code == session['reset_code']:
            flash('Reset code verified.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Incorrect reset code.', 'danger')
    
    return render_template('verify_reset_code.html')

# Reset Password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_code' not in session or 'reset_email' not in session:
        flash('Reset code expired.', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_new_password')
        
        if not all([new_password, confirm_password]):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('reset_password'))
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))
        
        user = User.query.filter_by(email=session['reset_email']).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            session.pop('reset_code')
            session.pop('reset_email')
            flash('Password updated.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')

# Change Password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_new_password')

        if not check_password_hash(user.password, current_password):
            flash('Current password incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        user.set_password(new_password)
        db.session.commit()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

class ContactSubmission(db.Model):
    __tablename__ = 'contact_submission'
    __table_args__ = {'extend_existing': True}  # Allow redefinition if the table already exists

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ContactSubmission {self.name}>'


# Contact Us form submission route
@app.route('/contact', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not all([name, email, message]):
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('contact_us'))

        # Save the message to the database
        contact_submission = ContactSubmission(name=name, email=email, message=message)
        db.session.add(contact_submission)
        db.session.commit()

        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('home'))  # Redirect to home page after form submission

    return render_template('contact_us.html')

# Admin route to view contact submissions
@app.route('/contact_submissions')
def view_contact_submissions():
    if 'username' not in session or session['username'] not in ['admin', 'Bad']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Fetch all contact submissions
    submissions = ContactSubmission.query.all()
    return render_template('contact_submissions.html', submissions=submissions)

# Start the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
