from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email
# from flask_wtf.recaptcha import RecaptchaField
from util.security import validate_strong_password

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[DataRequired(), validate_strong_password])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    # recaptcha = RecaptchaField()

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[DataRequired()])