# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:32:51 2023

@author: ilepoutre
"""


import datetime
import jwt
import json
from functools import wraps


from flask import Blueprint, g, current_app, make_response, request, render_template
from flask.json import jsonify
from .config import SECRET_KEY_JWT_ENCODE, BCRYPT_LOG_ROUNDS, SECRET_KEY_RESET_PWD, reset_pwd_url, NOREPLY_EMAIL
from .db.tables import  check_blacklist, User, Company, BlacklistToken, Role

from webargs import fields
from webargs.flaskparser import use_args

from .db.schemas import UserSchema  
from .db import get_or_create
from sqlalchemy.orm import joinedload

from itsdangerous import URLSafeTimedSerializer
    


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
    



def init_role(email):
    l_staff = ['@company.fr']
    is_staff = any([email.endswith(end) for end in l_staff])    
    return 'staff' if is_staff else 'client'



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
        
        
        
        d_user = {
            'first_name': first_name, 
            'email':email,
            'password': encrypted_password,
            'last_name': last_name,
            'phone': phone
        }
        
        try:
            role, _ = get_or_create(session=session, model=Role, defaults=None, name=init_role(email))
        except:
            role = None
            not_staff= True
        else:
            d_user['roles'] = [role]
            not_staff = role.name.lower() != 'staff'
        
        if not_staff: 
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
                
                data_status = UserSchema(only=("id", "email", "created", "roles",)).dump(user)
                
                responseObject = {
                    'status': 'success',
                    'data': data_status
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
    

    

@auth.route('/auth/logout', methods=['POST'])
def logout():
    
    auth_header = request.headers.get('Authorization')
    
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    
    if auth_token:    
        blacklist_token = BlacklistToken(token=auth_token)
        try:
            session = current_app.session  
            session.add(blacklist_token)
            session.commit()
            session.close()
            
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': e
            }
            return jsonify(responseObject)
            
        else:
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged out.'
            
            }
            return jsonify(responseObject)
    else:
        responseObject = {
            'status': 'fail',
            'message': 'No token given'
        }
        return jsonify(responseObject)
    




@auth.route('/auth/request-reset', methods=["POST"]) 
def request_reset():
    '''
    '''
    email_to_send_reset_pwd_link = request.json['email']
    session = current_app.session
    
    try:
        # Does user exist?
        q = session.query(User).filter(User.email == email_to_send_reset_pwd_link).one() 

    except:
        responseObject = {'message': 'User does not exist.'}
        return make_response(jsonify(responseObject), 401)
    
    else:
        
        ts = URLSafeTimedSerializer(SECRET_KEY_RESET_PWD)
        token = ts.dumps(email_to_send_reset_pwd_link, salt='reset-pwd')
        tokenized_reset_pwd_url = reset_pwd_url + ('?token=%s' % token)
        
        try:
            # html = render_template('reset_password.html', reset_pwd_url=tokenized_reset_pwd_url)
            # send_email_sendgrid(html=html, from_=NOREPLY_EMAIL, to=email_to_send_reset_pwd_link, subject="Reset pwd")  
            pass
        except:
            responseObject = {'message': 'Error when sending email' }
            return make_response(jsonify(responseObject), 500)
        else:
            
            responseObject = {'message': 'reset email sent at %s' % email_to_send_reset_pwd_link}
            return make_response(jsonify(responseObject), 200)    
    
    
    
    
@auth.route('/auth/confirm-reset', methods=["POST"]) 
def confirm_reset():
    '''
    '''

    request_get_json = request.get_json()
    reset_token = request_get_json.get('token','')

    ts = URLSafeTimedSerializer(SECRET_KEY_RESET_PWD)
    max_age_sec = 3600 * 24 * 100 # 100 jours
    email_decoded_from_token = ts.loads(reset_token, salt="reset-pwd", max_age=max_age_sec)

    session = current_app.session
    
    try:
        user = session.query(User).filter(User.email == email_decoded_from_token).one()
    except:         
        responseObject = {'message': 'Bad token'}
        return make_response(jsonify(responseObject), 401)        
    else:
        
        if not user.is_activated:
            responseObject = {'message': 'user is not activated'}
            return make_response(jsonify(responseObject), 401)                
        
        else:
            # User password is updated
            new_password = request_get_json.get('password')
            encrypted_password = g.bcrypt.generate_password_hash(new_password, BCRYPT_LOG_ROUNDS).decode()
            user.password = encrypted_password
            if not user.email_confirmed:
                user.email_confirmed = True
            
            session.commit()
            
            auth_token = encode_auth_token(user.id)
            responseObject = {'message': 'password successfully changed', 'data': {'auth_token': auth_token}}
            
            return make_response(jsonify(responseObject), 200)  



def login_required(func):
    
    """ 
    Execute function (and thus return sensitive jsonify data) if request contains valid access token. 
    Else return a unauthorized 401 response
    """
    @wraps(func)
    def decorated_route_function(*args, **kwargs):
        
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        
        auth_token = auth_token.strip().rstrip()

        # Bearer <TOKEN> in authorizarion header        
        if auth_token != '':
            decoded_user_id = decode_auth_token(auth_token)
            # decoding token works
            if not isinstance(decoded_user_id, str):
                
                session = current_app.session
                session.expire_on_commit = False
                
                try:
                    # user = session.query(User).outerjoin(Company).filter(User.id == decoded_user_id).one()
                    user = session.query(User).options(joinedload(User.company)).filter(User.id == decoded_user_id).one()
                    setattr(decorated_route_function, 'user', user)
                    assert user.id == decoded_user_id
                except:
                    return make_response(jsonify({'message':'Internal server error' }), 500)
                else:
                    if not user.is_activated:
                        return make_response(jsonify({'message':'User is not yet validated', 'status': 'Unauthorized'}), 401)
                    else:
                        return func(*args, **kwargs)
                    
            # resp is str <==> bad token
            else:
                return make_response(jsonify({'message':decoded_user_id, 'status': 'Unauthorized'}), 401) 

        else:
            return make_response(jsonify({'message':'No authorization header', 'status': 'Unauthorized'}), 401)    
        
    return decorated_route_function













