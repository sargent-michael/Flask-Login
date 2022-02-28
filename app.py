"""
    Author: Michael Sargent
    Class: SDEV-300
    Date: 2-19-2022
    Purpose: Lab 6 - Flask
"""

from datetime import datetime
import csv
import string
from passlib.hash import sha256_crypt
from flask import Flask, redirect, url_for, render_template, request, session, flash

creds = './resources/login.csv'

app = Flask(__name__)
app.secret_key = 'supersecretkey'


def check_complexity(pass_str):
    """ Function ensures registered password meets required complexity."""
    length = bool(len(pass_str) >= 12)
    lowercase = any(c in string.ascii_lowercase for c in pass_str)
    uppercase = any(c in string.ascii_uppercase for c in pass_str)
    numbers = any(c in string.ascii_lowercase for c in pass_str)
    spec_char = any(c in string.punctuation for c in pass_str)
    return bool(length and lowercase and uppercase and numbers and spec_char)


@app.route('/')
@app.route('/index')
def index():
    """Home page"""
    return render_template('index.html', title="Home Page",
                           description="This is the home page. Look below for other links:",
                           date=datetime.now().strftime("%H:%M %m/%d/%Y"),
                           authenticated=bool('user' in session))


@app.route('/about')
def about():
    """Display's the about page with an unordered list"""
    unordered = {"Charleston": "South Carolina", "Pasadena": "Maryland",
                 "San Angelo": "Texas", "San Antonio": "Texas", "Pensacola": "Florida"}
    return render_template('about.html',
                           title="About",
                           date=datetime.now().strftime("%H:%M %m/%d/%Y"),
                           unordered=unordered)


@app.route('/contact')
def contact():
    """Display's the contact page with the ordered list"""
    ordered = ["Name:", "Number:", "Location:"]
    return render_template('contact.html',
                           title="Contact Information",
                           date=datetime.now().strftime("%H:%M %m/%d/%Y"),
                           contact_list=ordered)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if len(username) < 4:
            flash('Username must be a minimum of 4 characters long.')
            return redirect(url_for('register'))
        with open(creds, 'r', encoding='utf8') as pass_file:
            reader = csv.reader(pass_file, delimiter=',')
            for row in reader:
                if username == row[0]:
                    flash('This username already exists.')
                    return redirect(url_for('register'))
        if not check_complexity(request.form['password']):  # Enforce password complexity
            flash('Password must be a minimum of 12 characters long and contain at \
                      least 1 lowercase, 1 uppercase, 1 special, and 1 number character.')
            return redirect(url_for('register'))
        pass_hash = sha256_crypt.hash(request.form['password'])
        with open(creds, 'a', encoding='utf8') as pass_file:
            writer = csv.writer(pass_file)
            writer.writerow([username, pass_hash])
        flash('Registered successfully!')
        return redirect(url_for('login'))
    return render_template('register.html',
                           title="Registration Page",
                           date=datetime.now().strftime("%H:%M %m/%d/%Y"))


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST': # Process login request
        username = request.form['username'].lower()
        password = request.form['password']
        with open(creds, 'r', encoding='utf8') as pass_file:
            reader = csv.reader(pass_file, delimiter = ',')
            for row in reader:
                if username == row[0]:
                    if sha256_crypt.verify(request.form['password'], row[1]):
                        session['user'] = username
                        flash('Welcome ' + username.title() + '!')
                        return redirect(url_for('index'))
        flash('Login failed. Username or password was incorrect.')
    return render_template('login.html', date=datetime.now().strftime("%H:%M %m/%d/%Y"))


@app.route('/logout')
def logout():
    """Function logs the user out of their session and returns to the Home page."""
    session.pop('user', None)
    flash('Logged out successfully!')
    return redirect('index')


@app.errorhandler(404)
def page_error(error):
    """ If the user enters a route that is not listed
        then it will redirect them to /index"""
    print(error)
    return redirect('index')


if __name__ == '__main__':
    app.run(debug=True)
