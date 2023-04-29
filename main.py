import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import datetime
from flask_gravatar import Gravatar



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="blogs")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'))
    post_comments = db.relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    comment_author = db.relationship("User", back_populates="comments")
    parent_post = db.relationship('BlogPost', back_populates="post_comments")
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    def __init__(self, text,comment_author, parent_post):
        self.text = text
        self.comment_author = comment_author
        self.parent_post = parent_post
# setup for logging users

class User(db.Model, UserMixin):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    blogs = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comment', back_populates='comment_author')

    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name


#db.create_all()

# Initialize the login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# initialize the app with the extension
db.init_app(app)
with app.app_context():
    db.create_all()


# crete admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abbort with 403 error
        if current_user.id != 1:
            return abort(403)
        # otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if request.method == "POST":
        password = request.form.get('password')
        hashed_password = werkzeug.security.generate_password_hash(password=password, method='pbkdf2:sha256',
                                                                   salt_length=8)
        name = request.form.get('name')
        email = request.form.get('email')
        password = hashed_password

        email_exists = User.query.filter_by(email=email).first()

        if email_exists:
            flash('You are already registered', category='error')
            return redirect(url_for('login'))
        elif len(name) < 2:
            flash('name is too short', category='error')
        elif len(password) < 6:
            flash('password is too short', category='error')
        else:
            user = User(name=name, email=email, password=password)
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)
            flash('user created', category='success')
            return redirect(url_for('get_all_posts'))
    return render_template('register.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password!', category='error')

        else:
            flash('user does not exists!', category='error')

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if request.method == 'POST':
        now = datetime.datetime.now()
        formatted_date = now.strftime("%B %d, %Y")
        if form.validate_on_submit():
            new_post = BlogPost(
                title=request.form.get('title'),
                subtitle=request.form.get('subtitle'),
                author=current_user,
                date=formatted_date,
                img_url=request.form.get('img_url'),
                body=request.form.get('body'))

            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, name=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET","POST"])
@admin_only
def edit_post(post_id):
    is_edit = True
    post = BlogPost.query.get(post_id)
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if request.method == "POST":
        post.title = request.form['title']
        post.subtitle = request.form['subtitle']
        post.author = post.author
        post.img_url = request.form['img_url']
        post.body = request.form['body']
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=form, current_user=current_user, is_edit=is_edit)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))





if __name__ == "__main__":
    app.run(debug=True)
