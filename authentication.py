# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:32:51 2023

@author: ilepoutre
"""


import datetime
import jwt

from flask import Blueprint, g, current_app, make_response
from flask.json import jsonify
from config import SECRET_KEY_JWT_ENCODE
from db.tables import  check_blacklist, User

from webargs import fields
from webargs.flaskparser import use_args




auth = Blueprint('auth', __name__)


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY_JWT_ENCODE, algorithms=["HS256"]) 
        is_blacklisted_token = check_blacklist(auth_token, g.MYSQL_ENGINE)
        if is_blacklisted_token:
            return 'Token blacklisted. Please log in again.'
        else:
            return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=0),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, SECRET_KEY_JWT_ENCODE, algorithm='HS256')
    
    except Exception as e:
        return e
    
    
    
@auth.route('/auth/email-exists', methods=['GET'])
@use_args({"email": fields.Str(required=True)}, location="query")
def email_exists(args):

    try:
        current_app.session.query(User).filter(User.email == args["email"]).one()
    except:
        dresult = {'data': False}
    else:
        dresult = {'data': True}        
    
    return make_response(jsonify(dresult), 200)    
    






    
    
    



