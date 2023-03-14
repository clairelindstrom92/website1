import flask
from passlib.hash import sha256_crypt
import os
import logging
from functools import wraps

app = flask.Flask(__name__)
app.secret_key = 'some_super_secret_key'


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password


# Populate the user_database list with some sample users
user_database = [User("admin", sha256_crypt.hash("password")), User("user1", sha256_crypt.hash("pass1"))]


with open(os.path.join(app.root_path, 'templates', 'CommonPasswords.txt'), 'r') as f:
    common_passwords = f.read().splitlines()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask.session.get('logged_in') is None:
            return flask.redirect(flask.url_for('login', next=flask.request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/home')
def home():
    """Home page function."""
    if flask.session.get('logged_in'):
        return flask.render_template('home.html')

    return flask.redirect(flask.url_for('login'))


# Logging setup
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'login_failures.log')
log_format = '%(asctime)s - %(message)s'
logging.basicConfig(filename=log_file, level=logging.INFO, format=log_format)


def get_password_from_database(username):
    """Get the stored password for the given username from the user_database."""
    for user in user_database:
        if user.username == username:
            return user.password
    return None


def update_password_in_database(username, password):
    """Update the password for the given username in the user_database."""
    for user in user_database:
        if user.username == username:
            user.password = password
            return True
    return False


def is_password_complex(password):
    """Check if the given password meets complexity requirements."""
    # Implement your password complexity rules here
    return len(password) >= 8


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login function."""
    if flask.request.method == 'POST':
        username = flask.request.form.get('login_username')
        password = flask.request.form.get('login_password')
        stored_password = get_password_from_database(username)
        if stored_password is not None and sha256_crypt.verify(password, stored_password):
            flask.session['logged_in'] = True
            flask.session['username'] = username
            return flask.redirect(flask.url_for('home'))

        flask.flash('Incorrect username or password.')
        logging.info(f'Login failure for username: {username} from IP: {flask.request.remote_addr}')
    return flask.render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register function."""
    if flask.request.method == 'POST':
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')
        if not username:
            error = 'Please enter your Username.'
        elif not password:
            error = 'Please enter your Password.'
        elif get_password_from_database(username) is not None:
            error = 'Username already taken.'
        elif password in common_passwords:
            error = 'Password is too common.'
        elif not is_password_complex(password):
            error = 'Password is not complex enough.'
        else:
            user_database.append(User(username, sha256_crypt.hash(password)))
            flask.flash('Registration successful. Please login.')
            return flask.redirect(flask.url_for('login'))
        flask.flash(error)
    return flask.render_template('register.html')


@app.route('/logout')
def logout():
    """Logout function."""
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))


@app.route('/password_update', methods=['GET', 'POST'])
@login_required
def password_update():
    """Password update function."""
    if flask.request.method == 'POST':
        current_password = flask.request.form.get('current_password')
        new_password = flask.request.form.get('new_password')
        confirm_password = flask.request.form.get('confirm_password')

        if new_password != confirm_password:
            flask.flash('New password and confirm password do not match.')
            return flask.render_template('password_update.html')

        username = flask.session.get('username')
        stored_password = get_password_from_database(username)

        if stored_password is not None and sha256_crypt.verify(current_password, stored_password):
            if new_password in common_passwords:
                flask.flash('New password is too common. Please choose a different password.')
            elif not is_password_complex(new_password):
                flask.flash('New password is not complex enough.')
            else:
                update_password_in_database(username, sha256_crypt.hash(new_password))
                flask.flash('Password updated successfully.')
                return flask.redirect(flask.url_for('home'))
        else:
            flask.flash('Incorrect current password.')

    return flask.render_template('password_update.html')

@app.route('/contact')
def contact():
    return flask.render_template('contact.html')


@app.route('/information')
def information():
    return flask.render_template('information.html')


if __name__ == '__main__':
    app.run(debug=True)
