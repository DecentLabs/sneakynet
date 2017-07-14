from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from passlib.hash import pbkdf2_sha512
from hashlib import sha256
import datetime
import re
import json
from os import path, makedirs, linesep
import dateutil.parser

NODE_NAME = "node1"

app = Flask(__name__)
app.secret_key = 'H4ckW33k'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class Object(object):
    pass

@app.route('/')
def home():
    return render_template("home.html")


# ##### AUTH ##### #


class User(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    username = db.Column(db.String(80), unique=True)
    hash = db.Column(db.String(80))

    home_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean(), default=False)
    admin = db.Column(db.Boolean(), default=False)
    active = db.Column(db.Boolean(), default=True)
    last_synced = db.Column(db.DateTime(), nullable=True)

    threads = db.relationship('Thread', backref='author', lazy='dynamic')
    messages = db.relationship('Message', backref='author', lazy='dynamic')

    def __init__(self, username, password, home_node=NODE_NAME, active=True, admin=True):
        self.username = self.get_fqn(username, home_node)
        if password is not None:
            self.hash = pbkdf2_sha512.hash(password)
        else:  # external users shouldn't have a local password
            self.hash = ""
        self.admin = admin

        self.home_node = home_node
        if home_node == NODE_NAME:
            self.external = False
        else:
            self.external = True
            self.last_synced = datetime.datetime.now()
        self.active = active

        hash_base = "{}{}".format(self.username, self.home_node)
        self.id = sha256(hash_base).hexdigest()

    def get_username(self):
        return self.username.split('@')[0]

    def sync_out(self):
        """
        Serializes the User for export
        """
        output_json = {
            "id": self.id,
            "username": self.get_username(),
            "active": self.active,
            "admin": self.admin,
        }
        return json.dumps(output_json)

    @classmethod
    def sync_in(cls, home_node, user_data):
        """
        Constructs a User Object from a dict.
        """
        user = cls(user_data["username"],
                   password=None,
                   home_node=home_node,
                   active=user_data["active"],
                   admin=user_data["admin"])
        return user

    @classmethod
    def sync_update(cls, home_node, user_data):
        """
        Inserts or updates a user from a dict.
        """
        now = datetime.datetime.now()
        user = cls.query.get(user_data["id"])
        if user is not None:
            user.active = user_data["active"]
            user.admin = user_data["admin"]
        else:
            user = cls.sync_in(home_node, user_data)
        user.last_synced = now
        db.session.add(user)
        db.session.commit()

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
            errors["username"].append("username aready exists")
        # password validation
        if password != password_confirm:
            errors["password"].append("passwords do not match")
        elif len(password) < 8:
            errors["password"].append("password must be at least 8 characters long")
        if sum(len(i) for i in errors.values()) != 0:
            return render_template("register.html", errors=errors)
        # user registration
        else:
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
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    flash("you need to be logged in to perform this action")
    return redirect(url_for("login"))


# #### BOARD #### #


class Thread(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    title = db.Column(db.String(110), unique=True)
    creation_time = db.Column(db.DateTime())
    last_message_time = db.Column(db.DateTime(), nullable=True)
    last_sync_time = db.Column(db.DateTime(), nullable=True)  # nullable
    last_sync_sent_time = db.Column(db.DateTime(), nullable=True)  # nullable

    sync_status = db.Column(db.String(20))

    source_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean(), default=False)

    author_id = db.Column(db.String(64), db.ForeignKey('user.id'))
    author_username = db.Column(db.String(80))
    messages = db.relationship('Message', backref='thread', lazy='dynamic', foreign_keys='Message.thread_id')
    children = db.relationship('Message', backref='parent_thread', lazy='dynamic', foreign_keys='Message.parent_thread_id')

    def __init__(self, title, author, source_node=NODE_NAME, creation_time=None):
        now = datetime.datetime.now()
        self.title = title + " [@{}]".format(source_node)
        self.author = author
        self.author_username = author.username
        self.last_message_time = now
        self.last_sync_time = None
        self.last_sync_sent_time = None
        self.sync_status = "posted"
        self.source_node = source_node
        self.external = False
        if source_node != NODE_NAME:
            self.external = True
            self.creation_time = creation_time
        else:
            self.creation_time = now

        hash_base = "{}{}{}{}".format(
            self.title,
            self.author_username,
            self.creation_time.isoformat(),
            self.source_node)
        self.id = sha256(hash_base).hexdigest()

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

    def sync_out(self):
        """
        Serializes the Thread for export
        """
        output_json = {
            "id": self.id,
            "title": self.title,
            "author": self.author_id,
            "author_username": self.author_username,
            "creation_time": self.creation_time.isoformat(),
        }
        return json.dumps(output_json)

    @classmethod
    def sync_in(cls, home_node, thread_data, author, creation_time):
        """
        Constructs a Thread Object from a json input string.
        """
        thread = cls(thread_data["title"].split(' [@')[0], author, home_node, creation_time=creation_time)
        return thread

    @classmethod
    def sync_update(cls, home_node, thread_data):
        now = datetime.datetime.now()
        creation_time = dateutil.parser.parse(thread_data["creation_time"])
        author = User.query.get(thread_data["author"])
        thread = cls.query.get(thread_data["id"])
        if thread is None:
            thread = cls.sync_in(home_node, thread_data, author, creation_time)
        thread.last_sync_time = now
        db.session.add(thread)
        db.session.commit()


class Message(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    author_id = db.Column(db.String(64), db.ForeignKey('user.id'))
    author_username = db.Column(db.String(80))
    content = db.Column(db.UnicodeText())
    thread_id = db.Column(db.String(64), db.ForeignKey('thread.id'))
    parent_id = db.Column(db.String(64), db.ForeignKey('message.id'), nullable=True)
    parent_thread_id = db.Column(db.String(64), db.ForeignKey('thread.id'), nullable=True)
    children = db.relationship('Message', backref=db.backref('parent', remote_side=id), lazy='dynamic',)
    post_time = db.Column(db.DateTime())
    last_sync_time = db.Column(db.DateTime(), nullable=True)
    last_sync_sent_time = db.Column(db.DateTime(), nullable=True)
    sync_status = db.Column(db.String(20))

    source_node = db.Column(db.String(80), nullable=True)
    external = db.Column(db.Boolean(), default=False)

    def __init__(self, author, content, parent_thread, parent_message=None, source_node=NODE_NAME, post_time=None):
        self.author = author
        self.author_username = author.username
        self.content = content
        self.parent_id = parent_message.id if parent_message is not None else None
        if parent_message:
            self.thread_id = parent_thread.id
        else:
            self.parent_thread_id = self.thread_id = parent_thread.id

        self.post_time = datetime.datetime.now()
        if post_time is not None:
            self.post_time = post_time
        self.sync_status = "posted"

        self.source_node = source_node
        self.external = False
        if source_node != NODE_NAME:
            self.external = True

        id_base = "{}{}{}{}".format(self.author_username, self.content, self.source_node, self.post_time.isoformat())
        self.id = sha256(id_base).hexdigest()

    def sync_out(self):
        """
        Serializes the Message for export
        """
        output_json = {
            "id": self.id,
            "source_node": self.source_node,
            "content": self.content,
            "author": self.author_id,
            "author_username": self.author_username,
            "post_time": self.post_time.isoformat(),
            "thread_id": self.thread_id,
            "parent_id": self.parent_id,
            "parent_thread_id": self.parent_thread_id
        }
        return json.dumps(output_json)

    @classmethod
    def sync_in(cls, home_node, message_data, author, parent_thread, parent_message):
        """
        Constructs a Message Object from a json input string.
        """
        post_time = dateutil.parser.parse(message_data["post_time"])
        message = cls(
            author,  # author
            message_data["content"],
            parent_thread,  # parent_thread
            parent_message=parent_message,
            source_node=home_node,
            post_time=post_time)
        message.post_time = post_time
        return message

    @classmethod
    def sync_update(cls, home_node, message_data):
        now = datetime.datetime.now()
        author = User.query.get(message_data["author"])
        parent_thread = Thread.query.get(message_data["thread_id"])
        parent_message = message_data["parent_id"]
        if parent_message is not None:
            parent_message = Message.query.get(message_data["parent_id"])
        message = cls.query.get(message_data["id"])
        if message is None:
            message = cls.sync_in(home_node, message_data, author, parent_thread, parent_message)
        message.last_sync_time = now
        db.session.add(message)
        db.session.commit()


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


@app.route("/board/thread/<string:thread_id>")
def display_thread(thread_id):
    thread = Thread.query.get(thread_id)
    messages = thread.get_messages_tree()
    return render_template("thread.html", thread=thread, messages=messages)


@app.route("/board/thread/<string:thread_id>/new", methods=["GET", "POST"])
@login_required
def new_message(thread_id):
    thread = Thread.query.get(thread_id)
    reply = request.args.get("reply", 0)
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


def do_sync_out(sync_dir_root, sequence_id):
    now = datetime.datetime.now()
    output_dir = path.join(sync_dir_root, NODE_NAME, sequence_id)
    if not path.isdir(output_dir):
        makedirs(output_dir)
    output_file_users = path.join(output_dir, "users.jsonl")
    output_file_threads = path.join(output_dir, "threads.jsonl")
    output_file_messages = path.join(output_dir, "messages.jsonl")
    # dump users
    users = User.query.filter_by(external=False)
    users_export = [user.sync_out() + linesep for user in users]
    with open(output_file_users, "w") as f:
        f.writelines(users_export)
    # dumps threads
    threads = Thread.query.filter_by(external=False).filter_by(sync_status="posted").order_by(Thread.creation_time)
    threads_export = [thread.sync_out() + linesep for thread in threads]
    with open(output_file_threads, "w") as f:
        f.writelines(threads_export)
    for thread in threads:
        thread.sync_status = "syncing"
        thread.last_sync_sent_time = now
    # dump messages
    messages = Message.query.filter_by(external=False).filter_by(sync_status="posted").order_by(Message.post_time)
    messages_export = [message.sync_out() + linesep for message in messages]
    with open(output_file_messages, "w") as f:
        f.writelines(messages_export)
    for message in messages:
        message.sync_status = "syncing"
        message.last_sync_sent_time = now


def do_sync_in(sync_dir_root, node_name, sequence_id):
    sync_mapping = {"users": {}, "threads": {}, "messages": {}}
    input_dir = path.join(sync_dir_root, node_name, sequence_id)
    input_file_users = path.join(input_dir, "users.jsonl")
    input_file_threads = path.join(input_dir, "threads.jsonl")
    input_file_messages = path.join(input_dir, "messages.jsonl")
    # load users
    with open(input_file_users, "r") as f:
        for line in f:
            if len(line):
                user_data = json.loads(line)
                User.sync_update(node_name, user_data)
    # load threads
    with open(input_file_threads, "r") as f:
        for line in f:
            if len(line):
                thread_data = json.loads(line)
                Thread.sync_update(node_name, thread_data)
    # load messages
        with open(input_file_messages, "r") as f:
            for line in f:
                if len(line):
                    message_data = json.loads(line)
                    Message.sync_update(node_name, message_data)


@app.route("/sync")
@login_required
def sync_home():
    if not current_user.is_admin:
        flash("restricted to admin users")
        return redirect(url_for("home"))
    return render_template("sync_home.html")


# #### MAIN #### #


if __name__ == '__main__':
    app.run(debug=True)