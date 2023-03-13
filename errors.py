# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:53:26 2023

@author: ilepoutre
"""


from flask_restful import Api
from flask.json import jsonify

from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.exceptions import HTTPException


# Custom Exceptions must have HTTPException as the base Exception
errors = {
    'UserAlreadyExistsError': {
        'message': "A user with that username already exists.",
        'status': 409,
    },
    'ResourceDoesNotExist': {
        'message': "A resource with that ID no longer exists.",
        'status': 410,
        'extra': "Any extra information you want.",
    },
}



class ExtendedAPI(Api):
    """
    This class overrides 'handle_error' method of 'Api' class ,
    to extend global exception handing functionality of 'flask-restful'.
    """
    def handle_error(self, err):
        """
        It helps preventing writing unnecessary
        try/except block though out the application
        """
        
        # Handle HTTPExceptions
        if isinstance(err, HTTPException):
            if str(err.code).startswith('4'):
                return super().handle_error(err)
            
            else:
                d_err_resp = {'message': getattr(err, 'description', HTTP_STATUS_CODES.get(err.code, ''))}
                return jsonify(d_err_resp), err.code
        
       
        # If msg attribute is not set, consider it as Python core exception 
        # and hide sensitive error info from end user
        if not getattr(err, 'message', None):
            return jsonify({'message': 'Server has encountered some error: %s' % str(err)}), 500
        
        
        # Handle application specific custom exceptions
        return jsonify(**err.kwargs), err.http_status_code






