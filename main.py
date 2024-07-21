import os
from flask import Flask, flash, render_template, session, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash

class Base(DeclarativeBase):
  pass

def valid_password(password):
    requirements = {
        'length': len(password) >= 8,
        'lowercase': any(c.islower() for c in password),
        'uppercase': any(c.isupper() for c in password),
        'ends_with_number': password[-1].isdigit() if password else False
    }
    return requirements

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRAC_MODIFICATIONS']='False'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key = True)
    firstname= db.Column(db.Text)
    lastname= db.Column(db.Text)
    email= db.Column(db.Text, unique = True, nullable = False)
    username= db.Column(db.Text, unique = True, nullable = False)
    password_hash= db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, firstname, lastname, email, username, password):
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.username = username
        self.set_password(password)

    def __repr__(self):
        return f"First Name: {self.firstname}; Last Name: {self.lastname}; Email: {self.email}; Username: {self.username}; Password: {self.password}"

with app.app_context():
    db.create_all()


class SignInForm(FlaskForm):
    username = StringField('Enter Your Username', validators = [InputRequired()])
    password = PasswordField('Enter Your Password', validators = [InputRequired()])
    submit = SubmitField('Sign In')

class SignUpForm(FlaskForm):
    username = StringField('Username', validators = [InputRequired()])
    password = PasswordField('Password', validators = [InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must be the same')])
    firstname = StringField('First Name', validators = [InputRequired()])
    lastname = StringField('Last Name', validators = [InputRequired()])
    email = StringField('Email', validators = [InputRequired()])
    submit = SubmitField('Sign Up')

@app.route('/', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user:
            if user.check_password(password):
                print("Password is correct")
                return redirect(url_for('secret_page'))
            else:
                flash("Password is incorrect", 'error')
        else:
            flash("Username is incorrect", 'error')
    return render_template('SignIn.html', form=form)
    
@app.route('/thank-you')
def thanks():
    return render_template('ThankYou.html')

@app.route('/secret-page')
def secret_page():
    return render_template('SecretPage.html')

@app.route('/sign-up', methods = ['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    requirements = {}
    valid = True

    if form.validate_on_submit():
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        username = form.username.data
        password = form.password.data
        new_user = User(firstname=firstname, lastname=lastname, email=email, username=username, password=password)
        requirements = valid_password(password)
        valid = all(requirements.values())
        if valid:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('thanks'))
        else:
            error_message = (f"Password did not meet one or more of the following requirements:\n"
                f"- Length >= 8\n"
                f"- Contains at least one lowercase letter\n"
                f"- Contains at least one uppercase letter\n"
                f"- Ends with a number\n"
                f"{requirements.values()}")
            print(error_message)
    return render_template('SignUp.html', form=form, requirements=requirements, valid=valid)

if __name__ == '__main__':
    app.run(debug=True)