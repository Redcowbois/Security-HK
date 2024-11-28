# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
from unicodedata import normalize
from hashlib import sha1, sha256
import requests
import pyotp
import qrcode
import yaml
from os import urandom
import zxcvbn
import hashlib
import bcrypt
import json
import datetime
from flask_session_captcha import FlaskSessionCaptcha
import uuid

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = uuid.uuid4().hex #'your_secret_key_here' 
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

#Configure captcha
app.config['CAPTCHA_ENABLE'] = True
app.config['CAPTCHA_INCLUDE_ALPHABET'] = False
app.config['CAPTCHA_INCLUDE_PUNCTUATION'] = False
app.config['CAPTCHA_LENGTH'] = 6
app.config['CAPTCHA_WIDTH'] = 160
app.config['CAPTCHA_HEIGHT'] = 60

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)
# Initialize FlaskSessionCaptcha
captcha = FlaskSessionCaptcha(app) 

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

#TEST ROUTE DO NOT FORGET TO REMOVE
@app.route('/test', methods = ['GET'])
def test():
    return render_template('test.html')

#TEST ROUTE DO NOT FORGET TO REMOVE
@app.route('/test_fail', methods = ['GET'])
def test_fail():
    return render_template('test_fail.html')

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    elif request.method == 'POST':
        userDetails = request.form

        #Signup Request
        if 'signup' in userDetails:
            username = userDetails['username']  
            password = normalize('NFKC', userDetails['password'])  #Normalized as per NIST requirements
            password_confirm = normalize('NFKC', userDetails['password_confirm'])  #Normalized as per NIST requirements
            
            #Check the password strength
            ps_strength = str(zxcvbn.zxcvbn('password', user_inputs=[username])["score"])
            strength_message = "Your password strength scored "+ps_strength+" points."

            #If password and password confirmation are different
            if password !=password_confirm:
                return render_template('signup.html', error="Passwords must be the same", password_strength=strength_message)
            #If password is shorter than 8 characters
            elif len(password) < 8:
                return render_template('signup.html', error="Password must at least be 8 characters", password_strength=strength_message)
            #If the password has been breached before

            password_hash = sha1(password.encode()).hexdigest()
            response = requests.get("https://api.pwnedpasswords.com/range/" + str(password_hash[0:5]))
            if (password_hash[5:].upper()) in response.content.decode():
                return render_template('signup.html', error="This password had previously been breached, it is not safe")
            
            #If password is good, redirect to 2FA
            return redirect(url_for('signup_auth', _username=username, _password=password))


        #Back to Login
        elif 'login' in userDetails:
            return redirect(url_for('index'))


@app.route('/signup_auth', methods=['GET', 'POST'])
def signup_auth():

    #For sign in button
    if request.method == 'POST' and ('login' in request.form):
        print("ran")
        return redirect(url_for('login'))
    
    #Creation of 2FA QrCode
    secret = pyotp.random_base32() 
    totp_auth = pyotp.totp.TOTP(secret).provisioning_uri(name=request.args.get('_username'), issuer_name='COMP3334 Chat') 
    qrcode.make(totp_auth).save("./static/qr_auth.png") 

    #Adding secret to database
    recovery_code = sha256(urandom(32)).hexdigest()
    cur = mysql.connection.cursor()
    hashedPass = cryptPass(request.args.get('_password'))
    propertiesJSON = json.dumps({"ip":request.remote_addr,"failedTries":0,"nextLogInAttempt":"now"})
    
    cur.execute("INSERT INTO users (username, password, auth_secret, recovery, properties) VALUES (%s, %s, %s, %s, %s)", 
                (request.args.get('_username'), 
                 hashedPass,
                 secret,
                 recovery_code,
                 propertiesJSON))
    mysql.connection.commit()
    cur.close()
    return render_template('signup_auth.html', recovery=recovery_code)
  


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':

        userDetails = request.form

        #Signup Request
        if 'signup' in userDetails:
            return redirect(url_for('signup'))

        if captcha.validate() != True: 
            return render_template('login.html', error="Wrong captcha")

        #Login Request
        if 'login' in userDetails:
            username = userDetails['username']
            password = normalize('NFKC', userDetails['password'])  
            cur = mysql.connection.cursor()

            cur.execute("SELECT user_id, password, properties FROM users WHERE username=%s", (username,))
            account = cur.fetchone()

            if not account:
                return render_template('login.html', error="Invalid credentials")

            #Fetch account properties
            accountJSON = json.loads(account[2])
            #If account has been attempted to log into over 100 times then lock account
            if accountJSON["failedTries"] > 99:
                return render_template('login.html', error="account locked")
            #If nextLogInAttempt is not "now" then the log in is in cooldown due to not putting the right password
            if accountJSON["nextLogInAttempt"] != "now":
                if(datetime.datetime.now()<datetime.datetime.strptime(accountJSON["nextLogInAttempt"], "%Y-%m-%d %H:%M:%S")):
                    timediff = (datetime.datetime.strptime(accountJSON["nextLogInAttempt"], "%Y-%m-%d %H:%M:%S")-datetime.datetime.now()).total_seconds()
                    message = "You have to wait ",timediff," seconds to try again."
                    return render_template('login.html', error=message)

            if comparePass(account[1],password):
                session['username'] = username
                session['user_id'] = account[0]       

                #If succesfull login then failedTries reset
                accountJSON["failedTries"] = 0
                #Next logInAttempt to now since it is a succesfull login (reset)
                accountJSON["nextLogInAttempt"] = "now"
                #Update the properties mentioned above.
                cur.execute("UPDATE users SET properties=%s WHERE user_id=%s",(json.dumps(accountJSON),account[0]))
                mysql.connection.commit()
                cur.close()
                print("before")
                return redirect(url_for('login_auth', _password=password, _user_id=account[0],_username=username))
                
            else:
                #Increment failedTries counter
                accountJSON["failedTries"] = accountJSON["failedTries"]+1
                #Calculate cooldown time for next log in attempt
                accountJSON["nextLogInAttempt"] = (datetime.datetime.now() + datetime.timedelta(seconds=min(187*accountJSON["failedTries"] - 157, 3600))).strftime("%Y-%m-%d %H:%M:%S")
                #Update properties mentioned above
                cur.execute("UPDATE users SET properties=%s WHERE user_id=%s",(json.dumps(accountJSON),account[0]))
                mysql.connection.commit()
                cur.close()
                error = 'Invalid credentials'
        
        #Test Branch
        else:
            return redirect(url_for('test_fail')) #Should be impossible, but is here to prevent crash just in case

    return render_template('login.html', error=error)


@app.route('/login_auth', methods=['GET', 'POST'])
def login_auth():
    error=None
    print("1")
    print(request.form)
    print(request.method)
    if request.method == 'GET':
        return render_template('login_auth.html')
    
    if request.method == 'POST' and ('totp' in request.form):
        print("Verifying timed code")
        totp = request.form['totp']
        password = request.args.get('_password')
        username = request.args.get('_username')

        print("2")
        #Get user secret from database
        cur = mysql.connection.cursor()
        print("2.2")
        cur.execute("SELECT auth_secret FROM users WHERE username=%s", (username,))
        print("2.3")
        secret = cur.fetchone()
        print("2.4")
        #cur.close()
        
        print("without 0: ",secret)
        print("secret:",secret[0])
        #Verify 2FA Timed One time password
        if pyotp.TOTP(secret[0]).verify(totp):
            print("Successful Login")
            session['username'] = request.args.get('_username')
            session['user_id'] = request.args.get('_user_id')
            return redirect(url_for('index'))
        else:
            print("Failed Login") 
            render_template('login_auth.html', error="Incorrect Timed One Time Password")

    print("3")
    if request.method == 'POST' and ('recovery' in request.form):
        print("Verifying recovery code")
        recovery = request.form['recovery']
        password = request.args.get('_password')
        username = request.args.get('_username')

        #Get user recovery code from database
        cur = mysql.connection.cursor()
        cur.execute("SELECT recovery FROM users WHERE username=%s", (username,))
        secret = cur.fetchone()
        cur.close()

        #Verify recovery code
        if recovery == secret:
            print("Successful Login")
            session['username'] = request.args.get('_username')
            session['user_id'] = request.args.get('_user_id')
            return redirect(url_for('index'))
        else:
            print("Failed Login") 
            render_template('login_auth.html', error="Incorrect recovery code")
    print("4")


@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s)", (sender, receiver, message,))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

#Function to hash/crypt passwords or any text basically
def cryptPass(plaintext):
    #hash with sha256 because bcrypt has 72 char limit
    sha256Pass = hashlib.sha256(plaintext.encode()).digest()
    #hash and salt with bcrypt
    completelyHashedPass = bcrypt.hashpw(sha256Pass,bcrypt.gensalt())
    return completelyHashedPass.decode("utf-8")

#function to compare hashed and salted password in db and the log in (user given) password
def comparePass(dbPass,plaitextPass):
    #hashing the plaintext pass bc we gave bcrypt the sha256 of the password before bcrypt
    sha256Pass = hashlib.sha256(plaitextPass.encode()).digest()
    #bcrypt function to compare
    if(bcrypt.checkpw(sha256Pass,dbPass)):
        return True
    else:
        return False
