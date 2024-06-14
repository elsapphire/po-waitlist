import os

from flask import Flask, render_template, request, redirect, url_for, abort, flash
from flask_login import UserMixin, login_user, login_required, current_user, LoginManager, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import String, Integer
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date


app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('LNK')

app.config['SECRET_KEY'] = os.environ.get('CSRF')


db = SQLAlchemy()
db.init_app(app)


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)


class Waitlisters(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False)
    wallet_address: Mapped[str] = mapped_column(String(100), nullable=True)
    date: Mapped[str] = mapped_column(String(100), nullable=False)


with app.app_context():
    db.create_all()


login_managerr = LoginManager()
login_managerr.init_app(app)


@login_managerr.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        try:
            if current_user.id != 1 and current_user.email != 'successabalaka2002@gmail.com':
                return abort(403)
        except AttributeError:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/waitlist', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        wallet_address = request.form['wallet_address']

        new_waitlister = Waitlisters(name=name,
                                     email=email,
                                     wallet_address=wallet_address,
                                     date=date.today().strftime("%B %d, %Y"),)
        db.session.add(new_waitlister)
        db.session.commit()

        joined = True
        print(joined)
        return render_template('index.html', joined=joined)
    elif request.method == 'GET':
        joined = False
    return render_template('index.html', joined=joined)


@app.route('/waitlist/success')
def success():
    return render_template('success.html')


@app.route('/waitlist/register-admin', methods=['GET', 'POST'])
@admin_only
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, salt_length=8, method='pbkdf2:sha256')

        # print(name, email, password)

        new_user = User(name=name,
                        email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(user=new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/waitlist/admin-login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # print(user)
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', user=current_user)


@app.route('/waitlist/admin-dashboard')
@login_required
def dashboard():
    waitlisters = db.session.execute(db.select(Waitlisters)).scalars().all()
    num_of_waitlisters = len(waitlisters)
    return render_template('dashboard.html', user=current_user, waitlisters=waitlisters,
                           num_of_waitlisters=num_of_waitlisters)


@app.route('/waitlist/waitlist-table')
@login_required
def table():
    waitlisters = db.session.execute(db.select(Waitlisters)).scalars().all()
    return render_template('tables.html', user=current_user, waitlisters=waitlisters)


@app.route('/waitlist/view-admins')
@admin_only
def admins():
    admin_users = db.session.execute(db.select(User)).scalars().all()
    return render_template('admins.html', admins=admin_users, user=current_user)


@app.route('/waitlist/delete_admin')
@admin_only
def delete_admin():
    admin_id = request.args.get('id')
    admin = db.session.execute(db.select(User).where(User.id == admin_id)).scalar()
    db.session.delete(admin)
    db.session.commit()
    return redirect(url_for('admins'))


@app.route('/waitlist/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=False)

