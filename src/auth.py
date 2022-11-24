from os import access
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT
from flask import Blueprint, app, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from flasgger import swag_from
from src.database import User, db
from datetime import timedelta
from flask_cors import CORS


auth = Blueprint("auth", __name__, url_prefix="/auth")
cors = CORS(auth, resources={r"/*": {"origins": "*"}})


@auth.post('/register')
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    pwd_hash = generate_password_hash(password)

    user = User(username=username, password=pwd_hash, email=email)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': "User created",
        'user': {
            'username': username, "email": email
        }

    }), HTTP_201_CREATED


@auth.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    print('username:', username, '\n password:', password)

    test = User.query.filter(User.email == username, User.password == password).first()
    print('test:', test)
    if test == None:
        return jsonify({"msg": "Bad email or password"}), 401
    refresh_token = create_refresh_token(
        identity=username, expires_delta=timedelta(minutes=10))
    access_token = create_access_token(
        identity=username, expires_delta=timedelta(seconds=10))
    return jsonify(refresh_token=refresh_token, access_token=access_token)


@auth.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@auth.route('/refresh_token', methods=['GET'])
@jwt_required(refresh=True)
def update_text():
    # username = request.json.get("username", None)
    # password = request.json.get("password", None)
    # access_token = create_access_token(
    #     identity=username, expires_delta=timedelta(seconds=10))
    # return jsonify(access_token=access_token)

    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

@auth.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    return jsonify({
        'username': user.username,
        'email': user.email
    }), HTTP_200_OK


@auth.get('/token/refresh')
@jwt_required(refresh=True)
def refresh_users_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access': access
    }), HTTP_200_OK
