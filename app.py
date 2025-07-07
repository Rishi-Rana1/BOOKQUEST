from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
import os
import pymongo
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_login import login_required
from flask_cors import CORS
from werkzeug.datastructures import MultiDict
from flask import make_response



app = Flask(__name__)

load_dotenv()

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=False  # WARNING: only for localhost development
)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://127.0.0.1:5173"}})
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
connection = pymongo.MongoClient(os.getenv('MONGO'))
db = connection['BookReviewProject']
books_collection = db['books']
reading_plans_collection = db['reading_plans']
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

@login_manager.user_loader
def load_user(user_id):
    user = db.User.find_one({
        '_id': ObjectId(user_id)
    })

    return User(user)

class User(UserMixin):
    def __init__(self, user):
        self.id = str(user['_id'])
        self.name = user['name']
        self.username = user['username']
        self.password = user['password']


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username1):
        user = db.User.find_one({
            'username': username1.data
        })

        if user:
            raise ValidationError('Username already exists')
        
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# @app.route('/')
# def home():
#     books = list(books_collection.find())
#     print(books)
#     return render_template('index.html', books = books)

# @app.route('/', methods=['GET', 'POST'])
# def home():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = db.User.find_one({'username': form.username.data})

#         if user and Bcrypt().check_password_hash(user['password'], form.password.data):
#             login_user(User(user))
#             print(f"User {current_user.username} logged in")
#             return redirect(url_for('index'))
#         else:
#             flash('Invalid username or password', 'danger')

#     return render_template('login.html', form=form)

@app.route('/index')
@login_required
def index():
    books = list(books_collection.find({'user_id': ObjectId(current_user.id)}))
    print(books)
    return jsonify({"books": [{
        '_id': str(book['_id']),
        'title': book['title'],
        'author': book['author'],
        'genre': book['genre'],
        'year': book['year'],
        'rating': book['rating'],
        'review': book['review']
    } for book in books]})

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        genre = request.form.get('genre')
        year = request.form.get('year')
        rating = request.form.get('rating')
        review = request.form.get('review')

        book_data = {
            'title': title,
            'author': author,
            'genre': genre,
            'year': year,
            'rating': rating,
            'review': review,
            'user_id': ObjectId(current_user.id)
        }
        print(current_user)
        books_collection.insert_one(book_data)
        flash('Book added successfully!', 'success')

        return redirect(url_for('index'))

    return render_template('add_book.html')

@app.route('/delete_book/<book_id>', methods=['DELETE'])
def delete_book(book_id):
    book = books_collection.find_one({'_id': ObjectId(book_id), 'user_id': ObjectId(current_user.id)})
    if not book:
        return jsonify({'error': 'Unauthorized or book not found'}), 403
    result = books_collection.delete_one({'_id': ObjectId(book_id)})
    if result.deleted_count > 0:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False}), 400
    
@app.route('/edit_book/<book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = books_collection.find_one({'_id': ObjectId(book_id), 'user_id': ObjectId(current_user.id)})
    if not book:
        flash("Unauthorized access or book not found", "danger")
        return redirect(url_for('index'))
    if request.method == 'POST':
        updated_data = {
            'title': request.form.get('title'),
            'author': request.form.get('author'),
            'genre': request.form.get('genre'),
            'year': request.form.get('year'),
            'rating': request.form.get('rating'),
            'review': request.form.get('review')
        }
        books_collection.update_one({'_id': ObjectId(book_id), 'user_id': ObjectId(current_user.id)}, {'$set': updated_data})
        flash('Book updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_book.html', book=book)

@app.route('/reading_plans')
@login_required
def reading_plans():
    plans = list(reading_plans_collection.find({'user_id': ObjectId(current_user.id)}))

    for plan in plans:
        book_details = []
        books_read = 0
        for book in plan['books']:
            book_info = books_collection.find_one({'_id': ObjectId(book['book_id']), 'user_id': ObjectId(current_user.id)})
            if book_info:
                book_details.append({
                    'book_id': book['book_id'],
                    'title': book_info['title'],
                    'read': book['read']
                })
                if book['read']:
                    books_read += 1 
        
        plan['books'] = book_details
        plan['books_read'] = books_read
        plan['total_books'] = len(book_details)

    return render_template('reading_plan.html', plans=plans)


@app.route('/delete_reading_plan/<plan_id>', methods=['POST'])
@login_required
def delete_reading_plan(plan_id):
    result = reading_plans_collection.delete_one({
        '_id': ObjectId(plan_id), 
        'user_id': ObjectId(current_user.id) 
    })

    if result.deleted_count > 0:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Unauthorized or Plan Not Found'}), 403  # Return 403 Forbidden

@app.route('/add_reading_plan', methods=['GET', 'POST'])
@login_required
def add_reading_plan():
    if request.method == 'POST':
        name = request.form.get('name')
        due_date = request.form.get('due_date')
        selected_books = request.form.getlist('books')

        reading_plan = {
            'user_id': ObjectId(current_user.id),
            'name': name,
            'due_date': due_date,
            'books': [{'book_id': book_id, 'read': False} for book_id in selected_books]
        }
        reading_plans_collection.insert_one(reading_plan)
        return redirect(url_for('reading_plans'))

    books = list(books_collection.find({'user_id': ObjectId(current_user.id)}))
    return render_template('add_plan.html', books=books)


@app.route('/update_reading_plan/<plan_id>', methods=['POST'])
@login_required 
def update_reading_plan(plan_id):
    plan = reading_plans_collection.find_one({'_id': ObjectId(plan_id), 'user_id': ObjectId(current_user.id)})
    
    if not plan:
        return jsonify({'error': 'Plan not found or unauthorized access'}), 404

    book_id = request.form.get('book_id')

    updated_books = []
    for book in plan['books']:
        if book['book_id'] == book_id:
            book['read'] = not book.get('read', False)
        updated_books.append(book)

    reading_plans_collection.update_one(
        {'_id': ObjectId(plan_id), 'user_id': ObjectId(current_user.id)},
        {'$set': {'books': updated_books}}
    )
    return jsonify({'success': True, 'updated_books': updated_books})


@app.route('/get_reading_plan/<plan_id>', methods=['GET'])
@login_required
def get_reading_plan(plan_id):
    # Ensure the reading plan belongs to the current user
    plan = reading_plans_collection.find_one({'_id': ObjectId(plan_id), 'user_id': ObjectId(current_user.id)})

    if not plan:
        return jsonify({'error': 'Plan not found or unauthorized access'}), 404

    book_details = []
    books_read = 0
    for book in plan['books']:
        book_info = books_collection.find_one({'_id': ObjectId(book['book_id'])})
        if book_info:
            book_details.append({
                'book_id': book['book_id'],
                'title': book_info['title'],
                'read': book['read']
            })
            if book['read']:
                books_read += 1

    return jsonify({
        'name': plan['name'],
        'books': book_details,
        'books_read': books_read,
        'total_books': len(book_details)
    })


@app.route('/register', methods=['GET', 'POST'])
def register():
    data = request.get_json()
    print(data)
    form = RegistrationForm(formdata=MultiDict(data), meta={'csrf': False})
    print(form.name.data, form.username.data, form.password.data)
    if form.validate():
        form.validate_username(form.username)
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        user = {
            'name': form.name.data,
            'username': form.username.data,
            'password': hashed_password
        }

        db.User.insert_one(user)
        return jsonify({'message': 'Registration successful'}), 201
    else:
        errors = form.errors
        return jsonify({'errors': errors}), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    data = request.get_json()
    form = LoginForm(formdata=MultiDict(data), meta={'csrf': False})

    if form.validate():
        user = db.User.find_one({
            'username': form.username.data
        })
        
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            login_user(User(user))
            print(f"{current_user.is_authenticated} auth")
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    else:
        errors = form.errors
        return jsonify({'errors': errors}), 400

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/search_books', methods=['GET'])
@login_required 
def search_books():
    query = request.args.get('query', '').strip()
    search_filter = {
        'user_id': ObjectId(current_user.id),
        '$or': [
            {'title': {'$regex': query, '$options': 'i'}},
            {'author': {'$regex': query, '$options': 'i'}},
            {'genre': {'$regex': query, '$options': 'i'}}
        ]
    }

    books = list(books_collection.find(search_filter))

    return jsonify([{
        '_id': str(book['_id']),
        'title': book['title'],
        'author': book['author'],
        'genre': book['genre'],
        'year': book['year'],
        'rating': book['rating'],
        'review': book['review']
    } for book in books])

@login_manager.unauthorized_handler
def unauthorized():
    response = jsonify({'error': 'Unauthorized'})
    response.status_code = 401
    response.headers.add("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:5173'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return response

if __name__ == '__main__':
    app.run()