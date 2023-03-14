# -*- coding: utf-8 -*-
"""
Created on Mon Mar 13 11:03:54 2023

@author: ilepoutre
"""

import os
from .db import get_engine_from_engine_str

FLASK_ENV = os.environ.get('FLASK_ENV', 'dev')
SECRET_KEY_JWT_ENCODE = os.environ.get('FLASK_REST_API_SECRET_KEY_JWT_ENCODE', None)
MYSQL_ENGINE_STR = os.environ.get('FLASK_REST_API_MYSQL_ENGINE_STR', None)
MYSQL_ENGINE = get_engine_from_engine_str(MYSQL_ENGINE_STR)

BCRYPT_LOG_ROUNDS = 4



