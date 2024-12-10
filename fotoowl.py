from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

class BorrowRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    date_from = db.Column(db.Date, nullable=False)
    date_to = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), default='pending')  # 'pending', 'approved', 'denied'

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(email=data['email'], password=hashed_password, role=data['role'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={"id": user.id, "role": user.role})
        return jsonify({"token": access_token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.all()
    return jsonify([{"id": book.id, "title": book.title} for book in books]), 200

@app.route('/borrow', methods=['POST'])
@jwt_required()
def borrow_book():
    current_user = get_jwt_identity()
    data = request.json
    overlapping = BorrowRequest.query.filter(
        BorrowRequest.book_id == data['book_id'],
        BorrowRequest.date_from <= data['date_to'],
        BorrowRequest.date_to >= data['date_from'],
        BorrowRequest.status == 'approved'
    ).first()

    if overlapping:
        return jsonify({"message": "Book is already borrowed for these dates"}), 400

    borrow_request = BorrowRequest(
        user_id=current_user['id'],
        book_id=data['book_id'],
        date_from=datetime.strptime(data['date_from'], '%Y-%m-%d').date(),
        date_to=datetime.strptime(data['date_to'], '%Y-%m-%d').date()
    )
    db.session.add(borrow_request)
    db.session.commit()
    return jsonify({"message": "Borrow request submitted"}), 201

@app.route('/admin/requests', methods=['GET'])
@jwt_required()
def view_requests():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403

    requests = BorrowRequest.query.all()
    return jsonify([{
        "id": req.id,
        "user_id": req.user_id,
        "book_id": req.book_id,
        "date_from": req.date_from,
        "date_to": req.date_to,
        "status": req.status
    } for req in requests]), 200

@app.route('/admin/approve/<int:request_id>', methods=['POST'])
@jwt_required()
def approve_request(request_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403

    borrow_request = BorrowRequest.query.get(request_id)
    if not borrow_request:
        return jsonify({"message": "Request not found"}), 404

    borrow_request.status = 'approved'
    db.session.commit()
    return jsonify({"message": "Request approved"}), 200

@app.route('/admin/deny/<int:request_id>', methods=['POST'])
@jwt_required()
def deny_request(request_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403

    borrow_request = BorrowRequest.query.get(request_id)
    if not borrow_request:
        return jsonify({"message": "Request not found"}), 404

    borrow_request.status = 'denied'
    db.session.commit()
    return jsonify({"message": "Request denied"}), 200

# Initialize DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
