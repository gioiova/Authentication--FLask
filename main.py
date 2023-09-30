

from flask import Flask, render_template, redirect, url_for
from flask_login import UserMixin,login_user,LoginManager,login_required,current_user,logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,EmailField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt #TO HASH PASSWORDS

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "secretkey"
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20),nullable=False,unique=True)
    email = db.Column(db.String(30),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)



class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    email = EmailField(validators=[InputRequired(),Length(min=4,max=30)],render_kw={"placeholder":"email"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"password"})
    submit = SubmitField("Register")


    def validate_email(self,email):
        exisitng_user_email = User.query.filter_by(email=email.data).first()
        if exisitng_user_email:
            error_message = "That email is taken"
            raise ValidationError(error_message)
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            error_message = "That username already exists,Please choice a differen one"
            raise ValidationError(error_message)


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template("home.html")
@app.route('/login',methods=['GET','POST'])
def login():
    form =  LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() # sheamowmebs tuaris user
        if user: # tu user arsebobs
            if bcrypt.check_password_hash(user.password,form.password.data): # sheadarebs useris shekvanil parols da bazashi arsebuls
                login_user(user) #shevides
                return redirect(url_for('dashboard'))
    return  render_template('login.html',form=form)

@app.route('/dashboard',methods=['GET','POST'])
@login_required  #only access on dashboard when we are loggid in
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():  #rodesac davawvebit submits shemdeg moxdeba agi
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,password=hashed_password,email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login')) #registraciis shemdeg gadagagdebs loginze ro daloginde

    return render_template('register.html',form=form)

if __name__ == '__main__':
    app.run(debug=True)