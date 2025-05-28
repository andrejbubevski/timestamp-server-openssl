import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '610dccded57a12320c49a3486565891169f554b9b8207cea'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'timestamps.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TSA_CERT_PATH = os.path.join(BASE_DIR, 'tsa_cert.pem')
    TSA_KEY_PATH = os.path.join(BASE_DIR, 'tsa_key.pem')