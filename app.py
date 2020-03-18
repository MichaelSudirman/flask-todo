from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
from functools import wraps

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'thisissecret'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init db
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

# Decorator function
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'emssage':'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated


@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'payload': {'users': output}})


@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):

    # Check if user exists
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'payload': {'user': user_data}})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(public_id):

    # Check if user exists
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):

    # Check if user exists
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login', methods=['POST'])
def login():

    # Checking authorization
    if not request.get_json():
        return make_response(jsonify({'error': 'could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    else:
        username = request.get_json()['username']
        password = request.get_json()['password']

    if not username or not password:
        return make_response(jsonify({'error': 'could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    # Check if user exists
    user = User.query.filter_by(name=username).first()
    if not user:
        return make_response(jsonify({'error': 'could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    # Check if password is correct
    if not check_password_hash(user.password, password):
        return make_response(jsonify({'error': 'could not verify'}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    # generate token
    exp_date = str(datetime.datetime.utcnow() + datetime.timedelta(minutes=30))
    token = jwt.encode({'public_id': user.public_id,
                        'exp': exp_date}, app.config['SECRET_KEY'])

    return jsonify({'token': token.decode('UTF-8')})


if __name__ == '__main__':
    app.run(debug=True)
