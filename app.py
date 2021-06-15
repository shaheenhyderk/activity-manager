from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'dfsbherhgnvjsdbvkj3478398563jssdbfa'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    task = db.relationship('Task', backref='creator')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(256), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Boolean, nullable=False, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect('/home')
    else:
        return redirect('/login')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect('/home')
        return render_template('login.html',)
    else:
        username = request.form.get('username') 
        password = request.form.get('password') 
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect('/home')
        else:
            flash('Invalid username / password')
            return redirect('/login')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect('/home')
        return render_template('signup.html',)
    else:
        username = request.form.get('username') 
        password = request.form.get('password') 

        if User.query.filter_by(username=username).first() != None:
            flash('User alredy exits')
            return redirect('/signup')

        new_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username = username, password=new_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/home')


@app.route("/logout")
def logout():
    logout_user()
    return redirect('/login')

@app.route("/home")
def home():
    if not current_user.is_authenticated:
        return redirect('/login')
    else:
        completed_tasks = Task.query.filter_by(status=True, creator=current_user)
        pending_tasks = Task.query.filter_by(status=False, creator=current_user)
        return render_template('home.html', completed_tasks=completed_tasks, pending_tasks=pending_tasks)

@app.route("/create-task", methods=['POST'])
def create_task():
    task_name = request.form.get('task')
    date_time = request.form.get('date')
    
    task = Task(name=task_name, creator= current_user, date=datetime.strptime(date_time, '%Y-%m-%dT%H:%M'))
    db.session.add(task)
    db.session.commit()
    return redirect('/home')

@app.route("/update-task/<int:task_id>")
def update_task(task_id):
    task = Task.query.get(task_id)
    task.status = True
    db.session.add(task)
    db.session.commit()
    return redirect('/home')
    
@app.route("/delete-task/<int:task_id>")
def delete_task(task_id):
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    return redirect('/home')

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)