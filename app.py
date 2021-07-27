from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, scoped_session
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm, RegisterForm, LoginForm
from flask_gravatar import Gravatar
import uuid

Base = automap_base()
login_manager = LoginManager()


# USED TO OVERRIDE AUTO-RELATIONSHIP DETECTION IN BASE.PREPARE()
def ignore_relationships(*args, **kwargs):
    return None


class User(UserMixin, Base):
    __tablename__ = "user"
    posts = relationship("BlogPost", back_populates="user")
    comments = relationship("Comment", back_populates="user")


class BlogPost(Base):
    __tablename__ = "blog_posts"
    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")


class Comment(Base):
    __tablename__ = "comments"
    user_id = Column(Integer, ForeignKey("user.id"))
    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    user = relationship("User", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")


app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex
login_manager.init_app(app)
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
engine = create_engine('sqlite:///blog.db')
Base.prepare(engine, reflect=True, generate_relationship=ignore_relationships)
Session = scoped_session(sessionmaker(engine, expire_on_commit=False))


@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        return user


@login_manager.unauthorized_handler
def unauthorized():
    return render_template("unauthorized.html")


@app.route('/')
def get_all_posts():
    with Session() as session:
        posts = session.query(BlogPost)
        return render_template("index.html", all_posts=posts, user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            with Session() as session:
                pw_hash = generate_password_hash(
                                form.password.data,
                                method='pbkdf2:sha256',
                                salt_length=8
                            )
                new_user = User(
                    name=form.name.data,
                    email=form.email.data,
                    password=pw_hash)
                session.add(new_user)
                session.flush()
                login_user(new_user)
                session.commit()
                return redirect(url_for("get_all_posts"))
        except IntegrityError:
            flash("It looks like that email account has already been registered. Try logging in.")
            return redirect(url_for("login"))
    return render_template("register.html", form=form, user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            with Session() as session:
                user = session.query(User).filter_by(email=form.email.data).first()
                if user is not None:
                    pw_hash = user.password
                    if check_password_hash(pw_hash, form.password.data):
                        login_user(user)
                        next_page = request.args.get('next')
                        return redirect(next_page or url_for("get_all_posts"))
                    else:
                        flash("The password you entered is incorrect. Please try again")
                        return redirect(url_for("login"))
                else:
                    flash("No account has been created with that email address. Please try again.")
                    return redirect(url_for("login"))
    return render_template("login.html", form=form, user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    form = CommentForm()
    with Session() as session:
        requested_post = session.query(BlogPost).filter_by(id=post_id).first()
        return render_template("post.html", post=requested_post, form=form, user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.id
        )
        with Session() as session:
            session.add(new_post)
            session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    with Session() as session:
        post = session.query(BlogPost).filter_by(id=post_id).first()
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            body=post.body)
        if edit_form.validate_on_submit():
            edited_post = {
                "title": edit_form.title.data,
                "subtitle": edit_form.subtitle.data,
                "img_url": edit_form.img_url.data,
                "body": edit_form.body.data}
            session.query(BlogPost).filter_by(id=post_id).update(edited_post)
            session.commit()
            return redirect(url_for("show_post", post_id=post.id))
        return render_template("make-post.html", form=edit_form, user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    with Session() as session:
        post_to_delete = session.query(BlogPost).filter_by(id=post_id).first()
        session.delete(post_to_delete)
        session.commit()
        return redirect(url_for('get_all_posts'))


@app.route("/comment", methods=["POST"])
@login_required
def comment():
    post_id = request.args.get("post_id")
    new_comment = Comment(text=request.form["comment"],
                          user_id=current_user.id,
                          post_id=post_id)
    with Session() as session:
        session.add(new_comment)
        session.commit()
        return redirect(url_for("show_post", post_id=post_id))


# @app.route("/delete/<int:post_id>")
# @login_required
# def delete_comment():
#     comment_id = request.args.get("comment_id")
#     post_id = request.args.get("post_id")
#     with Session() as session:
#         comment = session.query(Comment).filter_by(id=comment_id).first()
#         session.delete(comment)
#         return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
