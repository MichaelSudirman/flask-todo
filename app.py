from flask import Flask, request, jsonify, make_response
from flask_cors import CORS, cross_origin
from os import path, getenv
from functools import wraps
from app.api.user import user
from app.api.todo import todo
from app.models.database import db

# Init app
app = Flask(__name__)
CORS(app)
basedir = path.abspath(path.dirname(__file__))
app.config['SECRET_KEY'] = getenv('SECRET_KEY')

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init db
db.init_app(app)


app.register_blueprint(user)
app.register_blueprint(todo)


if __name__ == '__main__':
    app.run(debug=True)
