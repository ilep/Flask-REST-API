# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:32:51 2023

@author: ilepoutre
"""


import datetime
import jwt
import json

from flask import Blueprint, g, current_app, make_response, request
from flask.json import jsonify
from .config import SECRET_KEY_JWT_ENCODE, BCRYPT_LOG_ROUNDS
from .db.tables import  check_blacklist, User, Company

from webargs import fields
from webargs.flaskparser import use_args

from .db.schemas import UserSchema  
from .db import get_or_create



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

    # Does the user exist in db?
    try:
        q = session.query(User).filter(User.email == d_request.get('email')).one()
    
    # User with given email not found ==> creation (with its company if not a staff and company not already in db)
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
            
            company_name = d_request.get('company', {}).get('company_name',None)
            siret =  d_request.get('company', {}).get('siret',None)
            d_company = {'company_name': company_name, 'siret':siret}       
            company, company_created = get_or_create(session=session, model=Company, defaults=d_company, siret=siret)
        else:
            company = None
        
        if company is not None:
            d_user['company'] = company 
        
        # user creation
        try:
            user, user_created = get_or_create(session, User, email=email, defaults=d_user)
            if user is None:
                message = 'get_or_create / user is None'
                make_response(jsonify({'message': message}), 500)
        except:
            message = 'Error get_or_create'
            make_response(jsonify({'message': message}), 500)
        
        # success            
        else:
            assert user_created
            assert user is not None
        
            # Email sent to staff to validate user as soon as possible
            text = '''
            ==================================== \n
            ACCOUNT REGISTERED / TO BE VALIDATED \n
            ==================================== \n
            Account registered (email = %s) \n
            Please review and validate asap. \n
            ''' % (email)
            
            # send_email_sendgrid(text=text, from_=NOREPLY_EMAIL, to=STAFF_EMAIL, subject="Account activation pending...")
            
            auth_token = encode_auth_token(user.id)
            responseObject = {'message': 'Successfully registered.', 'data':{'auth_token': auth_token}} 
            
            return make_response(jsonify(responseObject), 200)            
        
    # User already exists in db
    else:
        return make_response(jsonify({'message': r'User already exists. Please Log in.'}), 409)

   


# decorator webargs du coup
@auth.route('/auth/login', methods=['POST'])
def login():
    
    d_request = json.loads(request.data.decode("utf-8"))
    
    session = current_app.session

    try:
        user = session.query(User).filter(User.email == d_request.get('email')).one()
    
    # no user found
    except:
        
        responseObject = {
            'message': 'User does not exist.'
        }
        return make_response(jsonify(responseObject), 404)
    
    # user in db
    else:
        # user must be activated
        if not user.is_activated:
            responseObject = {
                'message': 'Utilisateur non activé'
            }            
            return make_response(jsonify(responseObject), 401)
        
        else:
            
            # check password 
            if not g.bcrypt.check_password_hash(user.password, d_request.get('password')):   
                responseObject = {"message": 'Mot de passe incorrect'}
                return make_response(jsonify(responseObject), 401)
            
            # password correct
            else:    
                auth_token = encode_auth_token(user.id)
                responseObject = {"message": 'Successfully logged in', "data": {'auth_token': auth_token}}
                return make_response(jsonify(responseObject), 200)


@auth.route('/auth/status', methods=['GET'])
def status():

    auth_header = request.headers.get('Authorization')
    
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''

    if auth_token:
        resp = decode_auth_token(auth_token)
        if not isinstance(resp, str):
            session = current_app.session
            try:
                user = session.query(User).filter(User.id == resp).one()
                session.commit()
            except:
                return jsonify({"message": "error"})
            else:
                
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'created': user.created,
                        'category': user.category
                    }
                }
                session.close()
                return jsonify(responseObject)
        
        
        else:
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return jsonify(responseObject)
    
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return jsonify(responseObject)
    

    
    



