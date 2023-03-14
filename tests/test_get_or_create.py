# -*- coding: utf-8 -*-
"""
Created on Tue Mar 14 10:17:46 2023

@author: ilepoutre
"""


import os

from db import get_or_create
from db import get_engine_from_engine_str


from db.tables import Company
from sqlalchemy.orm import sessionmaker


MYSQL_ENGINE_STR = os.environ.get('FLASK_REST_API_MYSQL_ENGINE_STR', None)
MYSQL_ENGINE = get_engine_from_engine_str(MYSQL_ENGINE_STR)


siret =  '0'*14
d_company = {'company_name': 'test_company', 'siret':siret}   

Session = sessionmaker(bind = MYSQL_ENGINE)
session = Session()    

company, company_created = get_or_create(session=session, model=Company, defaults=d_company, siret=siret)

session.close()




