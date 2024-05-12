from flask import Flask, render_template, request, redirect, url_for, abort
from flask_login import UserMixin, login_manager, login_user, login_required, current_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy import String, Integer
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'


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


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        wallet_address = request.form['wallet_address']

        new_waitlister = Waitlisters(name=name,
                                     email=email,
                                     wallet_address=wallet_address)
        db.session.add(new_waitlister)
        db.session.commit()

        return redirect (url_for('success'))
    return render_template('index.html')


@app.route('/success')
def success():
    return render_template('success.html')


if __name__ == '__main__':
    app.run(debug=True, host='192.168.43.237')

