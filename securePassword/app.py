from flask import Flask, request, jsonify, redirect, url_for, session
import bcrypt
import pyotp
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session

app = Flask(__name__)
app.secret_key = "your_secret_key"  #  strong secret key
app.config['SESSION_TYPE'] = 'filesystem'  #  filesystem to store sessions
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
Session(app)
# User Registration with bcrypt password hashing and TOTP generation
from flask import render_template

# User Registration Route
from flask import Flask, request, jsonify, render_template, session
import bcrypt
import pyotp

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Секрет для сессии

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  
        
        # Хэшируем пароль с  bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Преобразуем хэш в строку перед сохранением в сессии
        session['username'] = username
        session['email'] = email 
        session['password_hash'] = password_hash.decode('utf-8')  # Сохраняем хэш как строку

        return jsonify({
            "message": "User registered successfully.",
            "hash-password": password_hash.decode('utf-8')  # Отображаем хэш как строку
        }), 201
    
    return render_template('register.html')






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form['totp_code']

        # Проверка, есть ли в сессии данные
        if 'password_hash' in session:
            # Получаем хэш пароля из сессии
            password_hash = session['password_hash'].encode('utf-8')  # Преобразуем строку обратно в байты

            # Проверка пароля
            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                # Генерация TOTP-секрета для проверки кода
                totp = pyotp.TOTP(session['totp_secret'], digits=6)  # Генерация 6-значного кода
                if totp.verify(totp_code):  # Проверка введенного TOTP-кода
                    return jsonify({"message": "Login successful", "username": username}), 200
                else:
                    return jsonify({"message": "Invalid TOTP code."}), 401
            else:
                return jsonify({"message": "Invalid username or password."}), 401
        else:
            return jsonify({"message": "No session data, please register first."}), 400

    # Генерация TOTP для отображения на странице логина
    totp = pyotp.TOTP(pyotp.random_base32(), digits=6)
    totp_secret = totp.secret
    session['totp_secret'] = totp_secret  # Сохраняем TOTP-секрет для проверки кода при логине

    return render_template('login.html', totp_code=totp.now())  # Отображаем код TOTP на странице


 




# Password Reset Route (Using JWT for password reset)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Проверка, если email не в сессии
        if 'email' not in session:
            return jsonify({"message": "User not logged in, please register first."}), 400

        email = session['email']  # Получаем email из сессии

        # Генерация JWT токена для сброса пароля
        reset_token = jwt.encode(
            {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
            "your_jwt_secret_key", 
            algorithm="HS256"
        )

        return jsonify({
            "message": "Password reset token generated",
            "reset_token": reset_token
        }), 200

    # GET метод: показываем форму для ввода email
    return render_template('reset_password.html')



    # Confirm password reset using JWT token
@app.route('/reset_password_confirm', methods=['GET', 'POST'])
def reset_password_confirm():
    if request.method == 'POST':
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
        
        try:
            # Декодируем токен
            decoded_token = jwt.decode(reset_token, "your_jwt_secret_key", algorithms=["HS256"])
            email = decoded_token["email"]

            # Хэшируем новый пароль
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # В реальной системе обновите пароль для пользователя в базе данных по email
            session['password_hash'] = password_hash.decode('utf-8')  # Обновляем пароль в сессии для примера

            return jsonify({"message": "Password successfully reset."}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Reset token has expired."}), 400
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token."}), 400

    # GET: Показываем форму для ввода токена и нового пароля
    return render_template('reset_password_confirm.html')


# Deactivate Account (remove data from session)
@app.route('/deactivate_account', methods=['GET', 'POST'])
def deactivate_account():
    if request.method == 'POST':
        # Удаляем все данные из сессии (деактивация аккаунта)
        session.pop('username', None)
        session.pop('password_hash', None)
        session.pop('email', None)

        return jsonify({"message": "Account deactivated successfully."}), 200

    # GET метод: показываем страницу с кнопкой для деактивации
    return render_template('deactivate_account.html')

# Account Recovery Route (Sending a reset token)
@app.route('/account_recovery', methods=['GET', 'POST'])
def account_recovery():
    if request.method == 'POST':
        email = request.form['email']

        # Генерация JWT токена для восстановления аккаунта
        recovery_token = jwt.encode(
            {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
            "your_jwt_secret_key", 
            algorithm="HS256"
        )

        # В реальной системе этот токен должен быть отправлен на email
        # Для простоты мы возвращаем токен
        return jsonify({
            "message": "Account recovery token generated.",
            "recovery_token": recovery_token
        }), 200

    # GET метод: показываем форму для ввода email
    return render_template('account_recovery.html')

    
if __name__ == '__main__':
    app.run(debug=True)
@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"  # Выводим имя пользователя
    else:
        return redirect(url_for('login'))  # Если не залогинен, перенаправляем на страницу логина
