# -*- coding: utf-8 -*-
"""
Created on Thu May 27 10:13:38 2021

@author: ilepoutre
"""

import os
import argparse

from sqlalchemy_utils import database_exists, create_database
from sqlalchemy import create_engine
from sqlalchemy import text

from tables import Base



def init_db(mysql_engine):

    if not database_exists(mysql_engine.url):
        try:
            create_database(mysql_engine.url)
            Base.metadata.create_all(mysql_engine)
        except:
            print('db creation error')
    else:
        print('db already created')
        
        with mysql_engine.connect() as conn:
            l_databases = [d[0] for d in conn.execute(text("SHOW DATABASES;"))]
            assert mysql_engine.url.database in l_databases   
        
        with mysql_engine.connect() as conn:
            existing_tables = conn.execute(text('SHOW TABLES;'))
            l_existing_tables = [d[0] for d in existing_tables]    
            print('existing tables:')
            print(l_existing_tables)


def delete_db(mysql_engine):
    
    try:
        with mysql_engine.connect() as conn:
            conn.execute(text('drop database %s;' % mysql_engine.url.database))
    except:
        print("db not dropped. May be already deleted ")
    else:
        print("db deleted")


parser = argparse.ArgumentParser(
                    prog='Backend database management',
                    description='This programs allows to init / delete database'
                    )

parser.add_argument('action', help="create / delete")
parser.add_argument('varname', help="Name of the global env that contains the engine string") # FLAKS_REST_API_MYSQL_ENGINE_STR
args = parser.parse_args()

MYSQL_ENGINE_STR = os.environ[args.varname]
MYSQL_ENGINE = create_engine(MYSQL_ENGINE_STR, pool_pre_ping=True) # encoding='utf-8'

if args.action == "init":
    init_db(MYSQL_ENGINE)

elif args.action == "delete":
    delete_db(MYSQL_ENGINE)


# python db.py init FLASK_REST_API_MYSQL_ENGINE_STR     
# python db.py delete FLASK_REST_API_MYSQL_ENGINE_STR     

    














    