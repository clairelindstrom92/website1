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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not check_password_hash(user.password, form.password.data):
            # Log the failed login attempt
            app.logger.warning(
                f'Failed login attempt for user {form.username.data} from IP address {request.remote_addr}.')

            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout', methods=['GET'])
def logout():
    """Logout function."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/updatepassword', methods=['GET', 'POST'])
@login_required
def updatepassword():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        # Verify that the current password matches the one stored in the database
        if check_password_hash(current_user.password, current_password):
            # Validate the new password
            if validate_password(new_password):
                # Hash the new password and store it in the database
                hashed_password = generate_password_hash(new_password)
                current_user.password = hashed_password
                db.session.commit()
                flash('Your password has been updated.')
                return redirect(url_for('index'))
            else:
                flash(
                    'Your password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.')
        else:
            flash('Incorrect current password.')

    return render_template('updatepassword.html')





def get_common_passwords():
    with open('CommonPasswords.txt') as f:
        common_passwords = [line.strip() for line in f]
    return common_passwords

def validate_password(password):
    # Check password length and complexity
    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(
            char.isupper() for char in password) or not any(char.islower() for char in password):
        return False

    # Check if password is a common password
    common_passwords = get_common_passwords()
    if password in common_passwords:
        return False

    return True

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
