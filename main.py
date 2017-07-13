from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
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
    external = db.Column(db.Boolean(), default=False)
    admin = db.Column(db.Boolean(), default=False)
    active = db.Column(db.Boolean(), default=True)
    last_synced = db.Column(db.DateTime(), nullable=True)

    threads = db.relationship('Thread', backref='author', lazy='dynamic')
    messages = db.relationship('Message', backref='author', lazy='dynamic')

    def __init__(self, username, password, home_node=NODE_NAME, active=True):
        self.username = self.get_fqn(username, home_node)
        self.hash = pbkdf2_sha512.hash(password)

        self.home_node = home_node
        if home_node == NODE_NAME:
            self.external = False
        else:
            self.external = True
            self.last_synced = datetime.datetime.now()
        self.active = active

    def get_username(self):
        return self.username.split('@')[0]

    @staticmethod
    def get_fqn(username, node_name):
        return "{}@{}".format(username, node_name)

    def __repr__(self):
        return '<User %r>' % self.username

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def is_active(self):
        return self.active

    def get_id(self):
        return unicode(self.id)

    def is_admin(self):
        return self.admin


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = False
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        fqn = User.get_fqn(username, NODE_NAME)
        user = User.query.filter_by(username=fqn).first()
        if user is not None and pbkdf2_sha512.verify(password, user.hash) and user.active:
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
        fqn = User.get_fqn(username, NODE_NAME)
        user = User.query.filter_by(username=fqn).first()
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


@login_manager.unauthorized_handler
def unauthorized():
    flash("you need to be logged in to perform this action")
    return redirect(url_for("login"))


# #### BOARD #### #


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), unique=True)
    creation_time = db.Column(db.DateTime())
    last_message_time = db.Column(db.DateTime(), nullable=True)
    last_sync_time = db.Column(db.DateTime(), nullable=True)  # nullable
    last_sync_sent_time = db.Column(db.DateTime(), nullable=True)  # nullable

    sync_status = db.Column(db.String(20))

    source_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean(), default=False)
    source_id = db.Column(db.Integer, nullable=True)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author_username = db.Column(db.String(80))
    messages = db.relationship('Message', backref='thread', lazy='dynamic', foreign_keys='Message.thread_id')
    children = db.relationship('Message', backref='parent_thread', lazy='dynamic', foreign_keys='Message.parent_thread_id')

    def __init__(self, title, author, source_node=NODE_NAME, source_id=None):
        now = datetime.datetime.now()
        self.title = title
        self.author = author
        self.author_username = author.username
        self.creation_time = now
        self.last_message_time = now
        self.last_sync_time = None
        self.last_sync_sent_time = None
        self.sync_status = "posted"
        self.source_node = source_node
        self.external = False
        if source_node != NODE_NAME:
            self.external = True
        self.source_id = source_id

    def get_messages_tree(self, order="post"):
        return [self.recurse_children(msg, [], order=order) for msg in self.children]

    def recurse_children(self, current_node=None, dest_list=None, order="post"):
        if dest_list is None:
            dest_list = []
        if current_node is None:
            current_node = self
        children = current_node.children.order_by(Message.post_time)
        child_tree = []
        for child in children:
            child_tree.append( self.recurse_children(child, []))
        dest_list.append((current_node, child_tree))

        return (current_node, child_tree)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author_username = db.Column(db.String(80))
    content = db.Column(db.UnicodeText())
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    parent_thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=True)
    children = db.relationship('Message', backref=db.backref('parent', remote_side=id), lazy='dynamic',)
    post_time = db.Column(db.DateTime())
    last_sync_time = db.Column(db.DateTime(), nullable=True)
    last_sync_sent_time = db.Column(db.DateTime(), nullable=True)
    sync_status = db.Column(db.String(20))

    source_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean(), default=False)
    source_id = db.Column(db.Integer, nullable=True)

    def __init__(self, author, content, parent_thread, parent_message=None, source_node=NODE_NAME, source_id=None):
        self.author = author
        self.author_username = author.username
        self.content = content
        self.parent_id = parent_message.id if parent_message is not None else None
        if parent_message:
            self.thread_id = parent_thread.id
        else:
            self.parent_thread_id = self.thread_id = parent_thread.id
        self.post_time = datetime.datetime.now()
        self.sync_status = "posted"

        self.source_node = source_node
        self.external = False
        if source_node != NODE_NAME:
            self.external = True
        self.source_id = source_id


@app.route("/board")
def board_home():
    threads = {thread:thread.messages.count() for thread in Thread.query.all()}
    return render_template("board_home.html", threads=threads)


@app.route("/board/thread/new", methods=["GET", "POST"])
@login_required
def new_thread():
    errors = {"title": []}
    if request.method == "POST":
        title = request.form["title"]
        if len(title) > 80 or len(title) < 5:
            errors["title"].append("title must be more than 5 characters and less than 80 characters")
        thread = Thread.query.filter_by(title=title).first()
        if thread is not None:
            errors["title"].append("a thread with the same title already exists")
        if len(errors["title"]) == 0:
            thread = Thread(title, current_user)
            db.session.add(thread)
            db.session.commit()
            flash("thread created")
            return redirect(url_for("board_home"))
    return render_template("new_thread.html", errors=errors)


@app.route("/board/thread/<int:thread_id>")
def display_thread(thread_id):
    thread = Thread.query.get(thread_id)
    messages = thread.get_messages_tree()
    print(messages)
    return render_template("thread.html", thread=thread, messages=messages)


@app.route("/board/thread/<int:thread_id>/new", methods=["GET", "POST"])
@login_required
def new_message(thread_id):
    thread = Thread.query.get(thread_id)
    reply = int(request.args.get("reply", 0))
    if reply:
        reply_to = Message.query.get(reply)
        peers = reply_to.children.all()
    else:
        reply_to = False
        peers = thread.children.all()
    errors = {"content": []}
    if request.method == "POST":
        content = request.form["content"]
        if len(content) == 0:
            errors["content"].append("the message can't be empty")
        if len(errors["content"]) == 0:
            if reply_to:
                message = Message(current_user, content, thread, reply_to)
            else:
                message = Message(current_user, content, thread)
            db.session.add(message)
            db.session.commit()
            flash("message added")
            return redirect(url_for("display_thread", thread_id=thread.id))
    return render_template("new_message.html", thread=thread, reply_to=reply_to, peers=peers, errors=errors)


# #### SYNC #### #

if __name__ == '__main__':
    app.run(debug=True)