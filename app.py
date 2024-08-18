from flask import Flask, abort, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# creating flask login instance
login_manager = LoginManager(app)

# if user is not logged in(i.e @login_required failed) then redirect to 'login' view
login_manager.login_view = 'login'

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    complete = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Todo('{self.id}', '{self.text}', '{self.complete}')"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()



# register and login views
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! Welcome to your dashboard.'

# Todo routing
@app.route('/todos', methods=['GET', 'POST'])
@login_required
def todos():
    if request.method == 'POST':
        todo = Todo(text=request.form['todo'], complete=False, user_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
        flash('Todo created!', 'success')
        return redirect(url_for('todos'))
    todos = current_user.todos
    return render_template('todos.html', todos=todos)

@app.route('/todos/delete/<int:id>')
@login_required
def delete_todo(id):
    todo = Todo.query.get_or_404(id)
    if todo.user_id != current_user.id:
        abort(403)  # Forbidden
    db.session.delete(todo)
    db.session.commit()
    flash('Todo deleted!', 'success')
    return redirect(url_for('todos'))

@app.route('/todos/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_todo(id):
    todo = Todo.query.get_or_404(id)
    if todo.user_id != current_user.id:
        abort(403)  # Forbidden
    if request.method == 'POST':
        todo.text = request.form['todo']
        todo.complete = True if 'complete' in request.form else False
        db.session.commit()
        flash('Todo updated!', 'success')
        return redirect(url_for('todos'))
    return render_template('update_todo.html', todo=todo)


if __name__ == '__main__':
    app.run(debug=True)


'''
Documentation:
--------------

1. UserMixin Class
UserMixin class provides the implementation of these properties:
- has an is_authenticated() method that returns True if the user has provided valid credentials
- has an is_active() method that returns True if the user's account is active
- has an is_anonymous() method that returns True if the current user is an anonymous user
- has a get_id() method which, given a User instance, returns the unique ID for that object


'''