from flask import Flask, request, jsonify, make_response
from os import getenv
from flask import Blueprint
from ..models.models import Todo
from ..models.database import db
from ..util.util import token_required

todo = Blueprint('todo', __name__)
# Routes
@todo.route('/', methods=['GET'])
def index():
    return jsonify({'payload':'Hello World'})

@todo.route('/todos', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'payload': output})


@todo.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    # Checks for Todo
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return make_response({'error': 'Todo not found'}, 404)
    elif todo.user_id != current_user.id:
        return make_response({'error': 'Not authorized'}, 403)

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify({'payload': todo_data})


@todo.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['data'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo created'})


@todo.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    # Checks for Todo
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return make_response({'error': 'Todo not found'}, 404)
    elif todo.user_id != current_user.id:
        return make_response({'error': 'Not authorized'}, 403)

    todo.complete = True
    db.session.commit()

    return jsonify({'message': 'Todo item has been completed'})


@todo.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    # Checks for Todo
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return make_response({'error': 'Todo not found'}, 404)
    elif todo.user_id != current_user.id:
        return make_response({'error': 'Not authorized'}, 403)

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message': 'Todo item has been deleted'})
