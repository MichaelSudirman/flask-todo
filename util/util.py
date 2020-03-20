from flask import request, jsonify
from os import getenv
import jwt
from ..models.models import User
from functools import wraps


# Decorator function
def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, getenv('SECRET_KEY'))
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'error': 'Token is invalid!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated
