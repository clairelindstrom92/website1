from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
import os
import logging

app = Flask(__name__)
app.secret_key = 'some_super_secret_key'


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password


# Populate the user_database list with some sample users
user_database = [User("admin", "1234qwer"), User("user1", "pass1")]

# Load common passwords list
with open('static/CommonPasswords.txt', 'r') as f:
    common_passwords = f.read().splitlines()


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login function."""
    if request.method == 'POST':
        username = request.form.get('login_username')
        password = request.form.get('login_password')

        for user in user_database:
            if username == user.username and password == user.password:
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('home'))

        flash('Incorrect username or password.')
        logging.info(f'Login failure for username: {username}')

    return render_template('templates/login.html')


@app.route('/logout', methods=['GET'])
def logout():
    """Logout function."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
def index():
    """Index function."""
    return redirect(url_for('home'))


@app.route('/home', methods=['GET'])
def home():
    """Home function."""
    if not session.get('logged_in'):
        abort(401)

    return render_template('templates/home.html', username=session.get('username'))


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact function."""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        flash('Message sent!')

    return render_template('templates/contact.html')


@app.route('/information')
def information():
    """Render the information page."""
    return render_template('templates/information.html')


if __name__ == "__main__":
    app.run()
