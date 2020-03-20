from flask import request, jsonify, make_response
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from os import getenv
from jwt import encode
from flask import Blueprint
from ..models.models import User
from ..models.database import db
from ..util.util import token_required
import datetime

user = Blueprint('user', __name__)

# Routes
@user.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'error': 'Non-admin cannot perform that function!'}), 403

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


@user.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
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


@user.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid4()),
                    name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


@user.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    # Check if user exists
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted'})


@user.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    # Check if user exists
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@user.route('/login', methods=['POST'])
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
    exp_date = datetime.datetime.now() + datetime.timedelta(minutes=30)
    token = encode({'public_id': user.public_id,
                        'exp': exp_date}, getenv('SECRET_KEY'))

    return jsonify({'token': token.decode('UTF-8')})