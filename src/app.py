from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret-key-goes-here'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already taken')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile')
def profile():
    if current_user.is_authenticated:
        return render_template('profile.html', user=current_user)
    else:
        return redirect(url_for('login'))

@app.route('/index1')
def index1():
    if current_user.is_authenticated:
        return render_template('index1.html', user=current_user)
    else:
        return redirect(url_for('index11'))
    
@app.route('/index2')
def index2():
    if current_user.is_authenticated:
        return render_template('index2.html', user=current_user)
    else:
        return redirect(url_for('index22'))
    
@app.route('/index3')
def index3():
    if current_user.is_authenticated:
        return render_template('index3.html', user=current_user)
    else:
        return redirect(url_for('index33'))
    
@app.route('/index4')
def index4():
    if current_user.is_authenticated:
        return render_template('index4.html', user=current_user)
    else:
        return redirect(url_for('index44'))
    
@app.route('/index52')
def index52():
        return render_template('index52.html', user=current_user)

@app.route('/index11')
def index11():
        return render_template('index11.html', user=current_user)

@app.route('/index22')
def index22():
        return render_template('index22.html', user=current_user)

@app.route('/index33')
def index33():
        return render_template('index33.html', user=current_user)

@app.route('/index44')
def index44():
        return render_template('index44.html', user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5000)