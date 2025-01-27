from flask import Flask,redirect,render_template
from flask import session,send_file
from flask import request
from flask import make_response
from flask import url_for
from flask_sqlalchemy import SQLAlchemy

from flask_login import UserMixin,LoginManager,login_user,logout_user,login_required,current_user,logout_user
from werkzeug.security import generate_password_hash,check_password_hash
from flask import flash
app=Flask(__name__)
app.secret_key='HIHI@123'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///teachers.db'
db=SQLAlchemy(app)

login_manager=LoginManager()
login_manager.login_view='login'
login_manager.init_app(app)

class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True,autoincrement=True)
    name=db.Column(db.String(100),nullable=False)
    email=db.Column(db.String(100),unique=True,nullable=False)
    password=db.Column(db.String(100),nullable=False)
    
app.app_context().push()
db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def hello():
    return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()  # Or modify to check both email and username
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('profile'))  # Redirect to profile page upon successful login
    return render_template("login.html")

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'GET':
        return render_template("signup.html")
    
    # Use 'name' instead of 'username'
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    print(f"Received Name: {name}, Email: {email}")  # Debugging line

    # Check if the user already exists
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already exists')
        return redirect(url_for('signup'))
    
    # Create and save the new user
    new_user = User(name=name, email=email, password=generate_password_hash(password,method='pbkdf2:sha256'))
    db.session.add(new_user)
    db.session.commit()

    flash('Sign up successful!')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template("main.html", user=current_user)



app.run(debug=True)