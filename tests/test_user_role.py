# -*- coding: utf-8 -*-
"""
Created on Tue Mar 14 15:41:03 2023

@author: ilepoutre
"""

import os

from db import get_or_create
from db import get_engine_from_engine_str


from db.tables import User, Role
from sqlalchemy.orm import sessionmaker


MYSQL_ENGINE_STR = os.environ.get('FLASK_REST_API_MYSQL_ENGINE_STR', None)
MYSQL_ENGINE = get_engine_from_engine_str(MYSQL_ENGINE_STR)


Session = sessionmaker(bind = MYSQL_ENGINE)
session = Session()    

user, _ = get_or_create(session=session, model=User, defaults=None, email='')
user.roles

test_role = Role(name='client_premium')
user.roles = [test_role]

session.commit()
session.close()



Session = sessionmaker(bind = MYSQL_ENGINE)
session = Session()    
get_or_create(session=session, model=Role, defaults=None, name="clientbis")
session.close()

