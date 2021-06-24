from flask import Flask, render_template, redirect
from flask.helpers import send_from_directory, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate, upgrade
from flask_login import LoginManager, login_user, logout_user
from flask_login.mixins import UserMixin
from flask_login import login_required

from wtforms import StringField, PasswordField
from wtforms.validators import length, Email

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "THIS IS A SECRET"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sqlite.db"

Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager()
login.init_app(app)

@login.user_loader
def user_loader(user_id):
    return User.query.filter_by(id=user_id).first()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)

class LoginForm(FlaskForm):
    email = StringField("email", validators=[Email()])
    password = PasswordField("password", validators=[length(min=5)])

class RegisterForm(FlaskForm):
    email = StringField("email", validators=[Email()])
    password = PasswordField("password", validators=[length(min=5)])
    repeat_password = PasswordField("repeated_password", validators=[length(min=5)])



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if check_password_hash(user.password, form.password.data):
            login_user(user)

            return redirect(url_for("index"))

    return render_template("login.html", form=form)


@app.route("/register", methods = ["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit() and form.password.data == form.repeat_password.data:
        user = User(
            email=form.email.data, password=generate_password_hash(form.password.data)
        )

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("register.html", form=form)

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))



@app.route("/pictures/<filename>")
def pictures(filename):
    filename_full = "images/" + str(filename) + ".jpg"
    print(filename_full, flush=True)
    return send_from_directory('static', filename_full)

PIPENV_IGNORE_VIRTUALENVS=1

if __name__ == "__main__":
   app.run(debug = True)




