from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user
from passlib.hash import pbkdf2_sha512
import datetime
import re

NODE_NAME = "node1"

app = Flask(__name__)
app.secret_key = 'H4ckW33k'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/')
def home():
    return render_template("home.html")


# ##### AUTH ##### #


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    hash = db.Column(db.String(80), unique=True)

    home_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean())
    exists = db.Column(db.Boolean())
    last_synced = db.Column(db.DateTime(), nullable=True)

    threads = db.relationship('Thread', backref='person', lazy='dynamic')

    def __init__(self, username, password, home_node=NODE_NAME, exists=True):
        self.username = username
        self.hash = pbkdf2_sha512.hash(password)

        self.home_node = home_node
        if home_node == NODE_NAME:
            self.external = False
        else:
            self.external = True
            self.last_synced = datetime.datetime.now()
        self.exists = exists

    def __repr__(self):
        return '<User %r>' % self.username

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def is_active(self):
        return self.exists

    def get_id(self):
        return unicode(self.id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = False
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user is not None and pbkdf2_sha512.verify(password, user.hash):
            login_user(user)
            flash("login successful")
            return redirect(url_for('home'))
        error = True
    return render_template("login.html", error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    errors = {"username": [], "password": []}
    if request.method == "POST":
        print("got post request")
        username = request.form["username"]
        password = request.form["password"]
        password_confirm = request.form["password_confirm"]
        # username validation
        if len(username) < 5 or len(username) > 25:
            errors["username"].append("username must be between 5 and 25 characters")
        if not re.match(r'[a-zA-Z0-9]*', username):
            errors["username"].append("username must use alphanumeric characters only")
        user = User.query.filter_by(username=username).first()
        if user is not None:
            print("got user: {}".format(user))
            errors["username"].append("username aready exists")
        # password validation
        if password != password_confirm:
            errors["password"].append("passwords do not match")
        elif len(password) < 8:
            errors["password"].append("password must be at least 8 characters long")
        if sum(len(i) for i in errors.values()) != 0:
            print("erroring out")
            print("errors: {}".format(errors))
            return render_template("register.html", errors=errors)
        # user registration
        else:
            print("creating user")
            user = User(username, password)
            db.session.add(user)
            db.session.commit()
            flash("registration successful")
            return redirect(url_for("home"))
    return render_template("register.html", errors=errors)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("logout successful")
    return redirect(url_for("home"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# #### BOARD #### #


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), unique=True)
    creation_time = None
    last_message_time = None
    last_sync_time = None  # nullable
    last_sync_sent_time = None  # nullable
    author = None
    sync_status = db.Column(db.String(20))
    children = None  # nullable

    def __init__(self, title, author_id):
        now = datetime.datetime.now()
        self.title = title
        self.author = db.Column(db.Integer, db.ForeignKey('user.id'))
        self.creation_time = now
        self.last_message_time = now
        self.last_sync_time = None
        self.last_sync_sent_time = None
        self.sync_status = "posted"


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = None
    content = None
    parent = None  # nullable
    children = None  # nullable
    post_time = None
    last_sync_time = None
    last_sync_sent_time = None
    sync_status = db.Column(db.String(20))

    def __init__(self, author, content, parent_id):
        self.author = None
        self.content = content
        self.parent = None
        self.post_time = datetime.datetime.now()
        self.sync_status = "posted"


# #### SYNC #### #


@app.route("/board")
def board_home():
    return render_template("board_home.html")

if __name__ == '__main__':
    app.run(debug=True)