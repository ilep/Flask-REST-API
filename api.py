# -*- coding: utf-8 -*-
"""
Created on Fri Mar 10 19:55:29 2023

@author: ilepoutre
"""

import sys
print("Running with %s" % sys.executable)

from .errors import ExtendedAPI, errors
from .config import MYSQL_ENGINE, FLASK_ENV

from flask import Flask, g, _app_ctx_stack
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask.json import jsonify

from .authentication import auth, login_required

from sqlalchemy.orm import scoped_session, sessionmaker
from greenlet import getcurrent as _get_ident

from .db.schemas import UserSchema

app = Flask(__name__)
CORS(app)
api = ExtendedAPI(app, errors=errors)
bcrypt = Bcrypt(app)
app.register_blueprint(auth)
app.config['ENV'] = FLASK_ENV


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=MYSQL_ENGINE)
app.session = scoped_session(SessionLocal, scopefunc=_get_ident)
# app.session = scoped_session(SessionLocal, scopefunc=_app_ctx_stack.__ident_func__)


@app.teardown_appcontext
def remove_session(*args, **kwargs):
    app.session.remove()

@app.before_request
def before_request():
    g.bcrypt = bcrypt
    g.MYSQL_ENGINE = MYSQL_ENGINE


@app.route('/')
def hello_world():  
    return jsonify({'message':'hello world'})


@app.route('/user-only')
@login_required
def user_only_route():  
    data = UserSchema(only=("id", "email", "created", "roles",)).dump(user_only_route.user)
    return jsonify({'message':'Your are logged in', 'data': data})


# from .resources import  TestResource







