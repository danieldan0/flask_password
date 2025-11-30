from flask import Flask, redirect, render_template, flash, url_for
from flask_login import current_user, login_user
from config import Config
from extensions import db, login_manager, mail
from flask_mail import Message
from models import User
from forms import RegisterForm, LoginForm
import bcrypt
from util.tokens import generate_confirmation_token, confirm_token

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
login_manager.init_app(app)
setattr(login_manager, "login_view", "login")
mail.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return "Welcome to the Flask App!"

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Email not found, please register first")
            return redirect("/register")
        password_bytes = (form.password.data or "").encode("utf-8")
        stored_hash = (user.password_hash or "").encode("utf-8")
        if not bcrypt.checkpw(password_bytes, stored_hash):
            flash("Invalid password")
            return render_template("login.html", form=form)
        login_user(user)
        flash("Logged in successfully!")
        return redirect("/profile")
    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        pw = (form.password.data or "")
        confirm_pw = (form.confirm_password.data or "")
        if pw != confirm_pw:
            flash("Passwords do not match")
            return render_template("register.html", form=form)
        hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        user = User()
        user.email = form.email.data
        user.password_hash = hashed
        db.session.add(user)
        db.session.commit()

        # send activation email
        email_addr = user.email or ""
        if email_addr:
            token = generate_confirmation_token(email_addr)
            activate_url = url_for('activate', token=token, _external=True)
            try:
                msg = Message(subject="Activate your account",
                              recipients=[email_addr],
                              html=render_template('email/activate.html', activate_url=activate_url, user=user),
                              body=render_template('email/activate.txt', activate_url=activate_url, user=user))
                mail.send(msg)
            except Exception:
                # Don't break registration if email fails; log in real app
                pass

        flash("Registered successfully! Check your email to activate your account.")
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route("/profile")
def profile():
    return render_template("profile.html", user=current_user)


@app.route('/activate/<token>')
def activate(token):
    email = confirm_token(token, expiration=60 * 60 * 24)
    if not email:
        flash('The activation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Account not found for this activation link.', 'danger')
        return redirect(url_for('register'))
    user.is_active_account = True
    db.session.add(user)
    db.session.commit()
    flash('Account activated! You can now log in.', 'success')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)