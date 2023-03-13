# -*- coding: utf-8 -*-
"""
Created on Thu May 27 10:13:38 2021

@author: ilepoutre
"""

import os
import argparse

from sqlalchemy_utils import database_exists, create_database
from sqlalchemy import create_engine

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
        
        l_databases = [d[0] for d in mysql_engine.execute("SHOW DATABASES;")]
        assert mysql_engine.url.database in l_databases   
        
        existing_tables = mysql_engine.execute('show tables;')
        l_existing_tables = [d[0] for d in existing_tables]
        
        print('existing tables:')
        print(l_existing_tables)


def delete_db(d_config, db_name=None):
    
    port = 3306
    host = d_config.get('host')
    user = d_config.get('user')
    mdp = d_config.get('mdp')
    
    try:
        mysql_engine = create_engine('mysql+mysqlconnector://%s:%s@%s:%d/%s' % (user, mdp, host, port, db_name), encoding='utf-8')
        mysql_engine.execute('drop database %s;' % db_name)
    except:
        print("db not deleted")
    else:
        print("db deleted")


parser = argparse.ArgumentParser(
                    prog='Backend database management',
                    description='This programs allows to init / delete database'
                    )

parser.add_argument('varname', help="Name of the global env that contains the engine string") # FLAKS_REST_API_MYSQL_ENGINE_STR
parser.add_argument('action', help="create / delete")
args = parser.parse_args()

MYSQL_ENGINE_STR = os.environ[args.varname]
MYSQL_ENGINE = create_engine(MYSQL_ENGINE_STR, encoding='utf-8', pool_pre_ping=True)


print(f'MYSQL_ENGINE_STR = os.environ[{args.varname}] = {MYSQL_ENGINE_STR}')
print(f'{args.action}')


if args.action == "init":
    init_db(MYSQL_ENGINE)


    
# python .\db.py FLAKS_REST_API_MYSQL_ENGINE_STR init    

    














    