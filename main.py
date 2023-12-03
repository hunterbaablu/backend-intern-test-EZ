
import bcrypt
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


# Client User
@app.route("/", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s, %s, %s)", (name, email, password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template("register.html", form=form)


# operation User
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed.")
            return redirect(url_for('login'))

        return redirect(url_for('login'))

    return render_template("login.html", form=form)


# File Upload page with login details
@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if request.method == 'POST':
            f = request.files['file1']
            f.save(secure_filename(f.filename))
            flash("Uploaded successfully!")
            return redirect('/login')

        if user:
            return render_template('dashboard.html', user=user)
    return render_template("dashboard.html")


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logout.")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)