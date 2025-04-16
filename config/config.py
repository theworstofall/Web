import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'YOUR_SECRET_KEY')  # Fallback for dev
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Mail settings (update with your SMTP settings)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'dangolsujan2018@gmail.com'
    MAIL_PASSWORD = 'otpz mzrd yyan gmim'
    MAIL_DEFAULT_SENDER = 'dangolsujan2018@gmail.com'
    
    # Database URI (Use a raw string literal for Windows path)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, '..', 'instances', 'app.db')
