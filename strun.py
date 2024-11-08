from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from oauth2client.service_account import ServiceAccountCredentials
from werkzeug.security import generate_password_hash, check_password_hash
import gspread
from datetime import datetime
import os

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
app.secret_key = os.getenv('KEY')

# Initialize Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("ee-pinkeokkpm1-191b81cf96d8.json", scope)
client = gspread.authorize(creds)
sheet = client.open("STSCIN").sheet1

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

MAPBOX_ACCESS_TOKEN = os.getenv('MAPBOX_ACCESS_TOKEN') 
@app.route('/mapbox_token')
def mapbox_token():
    return jsonify({'token': MAPBOX_ACCESS_TOKEN})

MARKERS = [
    {"name": "Location 1", "lat": 17.857567, "lng": 102.609885, "type": "store"},
    {"name": "Location 2", "lat": 18.662874, "lng": 102.517810, "type": "restaurant"},
    {"name": "Location 3", "lat": 19.781189, "lng": 101.938082, "type": "park"}
]



@app.route('/get-markers')
def get_markers():
    return jsonify(MARKERS)



# User model
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        records = sheet.get_all_records()
        user_data = next((r for r in records if r["id"] == int(user_id)), None)
        if user_data:
            return User(user_data["id"], user_data["username"], user_data["email"])
    except Exception as e:
        print(f"Error loading user: {e}")
    return None

# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        records = sheet.get_all_records()
        if any(record["username"] == username.data for record in records):
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        records = sheet.get_all_records()
        if any(record["email"] == email.data for record in records):
            raise ValidationError('That email is taken. Please choose a different one.')

# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = {
            "id": len(sheet.get_all_records()) + 1,
            "username": form.username.data,
            "email": form.email.data,
            "password": hashed_password,
            "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        sheet.append_row(list(new_user.values()))
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        records = sheet.get_all_records()
        user_data = next((u for u in records if u["email"] == form.email.data), None)
        if user_data and check_password_hash(user_data["password"], form.password.data):
            user = User(user_data["id"], user_data["username"], user_data["email"])
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/landing')
def about():
    return render_template('landing.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    # Your contact form handling code here
    return render_template('landing.html')


@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('index.html',  markers=MARKERS)
    else:
        return render_template('landing.html')

# Other routes remain the same...

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
