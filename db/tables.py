# -*- coding: utf-8 -*-
"""
Created on Thu May 27 10:05:11 2021

@author: ilepoutre
"""


from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey, Column, Integer, String, Unicode, DateTime, Boolean, Text, Float
from sqlalchemy import VARCHAR

from sqlalchemy.orm import relationship
from sqlalchemy import Table
from sqlalchemy.sql import func

import datetime
from sqlalchemy.orm import sessionmaker



def has_id(row):
    bool_has_id =  hasattr(row, "id")
    if bool_has_id:
        bool_has_id = row.id is not None
    return bool_has_id

def has_attr_not_none(o, attr_name):
    bool_has_attr_not_none =  hasattr(o, attr_name)
    if bool_has_attr_not_none:
        bool_has_attr_not_none = o[attr_name] is not None
    return bool_has_attr_not_none
    

class TimestampMixin(object):
    
    # https://stackoverflow.com/questions/13370317/sqlalchemy-default-datetime
    created = Column(DateTime, nullable=False, server_default=func.now())
    updated = Column(DateTime, onupdate=func.now())
    

Base = declarative_base()


class ExtendedBase(Base):
    
    
    __abstract__ = True
    
    def __repr__(self, tab=0):
        
        str_repr = "<%s>\n" % self.__class__.__name__
        decal = ' ' *  tab * 4
            
        for c in [column.key for column in self.__table__.columns]:
            v = str(getattr(self,c)) if getattr(self,c) is not None else 'None'
            str_repr += '%s- %s = %s\n' %(decal, c, v)  

        return str_repr        
    
    def equals(self, other, *l_attrs):        
        return all([getattr(self, attr) == getattr(other, attr) for attr in l_attrs])        
    

class File(ExtendedBase): 
    
    __tablename__ = 'file'

    id = Column(Integer, primary_key = True, autoincrement=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(VARCHAR(1024), nullable=False)
    creation_date = Column(DateTime)


    
class Company(ExtendedBase, TimestampMixin):

    __tablename__ = "company"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    company_name = Column(String(100))
    siret = Column(String(25), unique=True, nullable=False)
    users = relationship("User", back_populates="company", cascade="all,delete-orphan")



user_role_association_table = Table(
    "user_role",
    Base.metadata,
    Column("user_id", ForeignKey('user.id', ondelete='CASCADE')), # primary_key=True
    Column("role_id", ForeignKey('role.id', ondelete='CASCADE')) # primary_key=True
)



class User(ExtendedBase, TimestampMixin):
    
    """ User Model for storing user related details """
    
    __tablename__ = "user"
    
    id =  Column(Integer, primary_key=True, autoincrement=True)
    
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False, default="*")
    first_name = Column(String(50))
    last_name = Column(String(50))
    phone = Column(String(20))
    is_activated = Column(Boolean, nullable=False, default=False)
    is_email_confirmed = Column(Boolean, nullable=False, default=False)

    company_id = Column(Integer, ForeignKey('company.id'))
    company = relationship("Company", back_populates="users")
    
    roles = relationship('Role', secondary = user_role_association_table)
    
    
# Define the Role data-model
class Role(ExtendedBase):
    
    __tablename__ = 'role'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    







class BlacklistToken(ExtendedBase):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_token'

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(500), unique=True, nullable=False)
    blacklisted_on = Column(DateTime, nullable=False)
    
    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()



def check_blacklist(auth_token, MYSQL_ENGINE):
    
    '''
    '''
    
    # check whether auth token has been blacklisted
    Session = sessionmaker(bind = MYSQL_ENGINE)
    session = Session()
    
    # res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
    q = session.query(BlacklistToken).filter(BlacklistToken.token == str(auth_token)).first()
    session.commit()
    
    if q is not None:
        session.close()
        return True  
    else:
        session.close()
        return False





    
    





