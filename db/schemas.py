# -*- coding: utf-8 -*-
"""
Created on Fri Nov 19 16:04:33 2021

@author: ilepoutre
"""


from marshmallow import Schema, fields, post_load
from marshmallow import validate, ValidationError
from marshmallow import validates_schema

# from  marshmallow.validate import Range
import datetime
import uuid


from .tables import Company, User, Role


class CompanySchema(Schema):
   
    id = fields.Integer()   
    company_name = fields.Str(required=True, allow_none=True)
    siret = fields.Str(validate=validate.Length(equal=14), required=True, allow_none=False)
    
    @post_load
    def make_company(self, data, **kwargs):
        return Company(**data)



class RoleSchema(Schema):
    
    id = fields.Integer()
    name = fields.Str()


    @post_load
    def make_role(self, data, **kwargs):     
        return Role(**data)    
    
class UserSchema(Schema):
    
    id = fields.Integer()
    name = fields.Str()
    email = fields.Email(allow_none=False, required=True)
    password = fields.Str()
    
    first_name = fields.Str(required=True, allow_none=True)
    last_name = fields.Str(required=True,allow_none=True)
    
    phone = fields.Str(required=True, allow_none=True)
    category = fields.Str()
    is_activated = fields.Boolean()
    is_email_confirmed = fields.Boolean()
    

    company_id = fields.Integer()    
    company = fields.Nested(CompanySchema, required=True)

    roles = fields.List(fields.Nested(RoleSchema(exclude=('id',))))

    @post_load
    def make_user(self, data, **kwargs):     
        return User(**data)


  
    
    
    
    