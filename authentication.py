# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:32:51 2023

@author: ilepoutre
"""


import datetime
import jwt

from flask import Blueprint, g, current_app, make_response, request
from flask.json import jsonify
from .config import SECRET_KEY_JWT_ENCODE, BCRYPT_LOG_ROUNDS
from .db.tables import  check_blacklist, User, Company

from webargs import fields
from webargs.flaskparser import use_args

from .db.schemas import UserSchema  

from .db import get_or_create
from .db.tables import get_or_create_company

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
    



def init_category(email):
    
    l_staff = ['@company.fr']
    
    is_staff = any([email.endswith(end) for end in l_staff])    
    
    if is_staff:
        return 'staff'
    else:
        return 'client'


@auth.route('/auth/register', methods=['POST'])
def register():
    
    d_request = request.get_json()
    
    errors = UserSchema().validate(d_request)
    if errors != {}:
        return make_response(errors, 401)
        
    session = current_app.session   

    # does the user exist in db?
    try:
        q = session.query(User).filter(User.email == d_request.get('email')).one()
        
    # user with given email not found ==> creation with company
    except:

        email = d_request.get('email')
        password = d_request.get('password')
        encrypted_password = g.bcrypt.generate_password_hash(password, BCRYPT_LOG_ROUNDS).decode()
        first_name = d_request.get('first_name', None)
        last_name = d_request.get('last_name', None)
        phone = d_request.get('phone', None)
        category = d_request.get('category', init_category(email.lower())) 
        
        d_user = {
            'first_name': first_name, 
            'email':email,
            'password': encrypted_password,
            'last_name': last_name, 
            'category':category, 
            'phone': phone
        }
        
        if category.lower() != 'staff': 
            d_company = {'company_name': d_request.get('company', {}).get('company_name',None), 'siret': d_request.get('company', {}).get('siret',None)}            
            company = get_or_create_company(d_company)

        else:
            company = None
            
        if company is not None:
            d_user['company'] = company 
        
        
        # user creation
        try:
            user, user_created = get_or_create(session, User, email=email, defaults=d_user)
            if user is None:
                message = 'get_or_create: user is None'
                make_response(jsonify({'message': message}), 500)
        except:
            message = 'Error in get_or_create'
            make_response(jsonify({'message': message}), 500)
            
        else:
            assert user_created
            assert user is not None
        
            text = '''
            ==================================== \n
            ACCOUNT REGISTERED / TO BE VALIDATED \n
            ==================================== \n
            Account registered (email = %s) \n
            Please review and validate asap. \n
            ''' % (email)
            
            # alert email sent to staff
            # send_email_sendgrid(text=text, from_=NOREPLY_EMAIL, to=STAFF_EMAIL, subject="Account activation pending...")
            
            auth_token = encode_auth_token(user.id)
            responseObject = {'message': 'Successfully registered.', 'data':{'auth_token': auth_token}} 
            
            return make_response(jsonify(responseObject), 200)            

    # user already exists in db
    else:
        return make_response(jsonify({'message': r'User already exists. Please Log in.'}), 409)

   






    
    
    



