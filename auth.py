import bcrypt
import pymongo
from settings import *
# Conector oficial do MongoDB
from pymongo import MongoClient

# Cria a hash de password
def hash_password(pw):
    pwhash = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt())
    return pwhash.decode('utf8')

# Verifica a hash de senha
def check_password(pw, hashed_pw):
    expected_hash = hashed_pw.encode('utf8')
    return bcrypt.checkpw(pw.encode('utf8'), expected_hash)

def groupfinder(username, request):
    # Obtém a coleção de usuários
    db = MongoClient(
        host=DB_HOST,
        port=DB_PORT
    )
    users = db[DB_NAME]['users']
    user = users.find_one({'username': username})
    return user

def hashed_password(username):
    # Obtém a coleção de usuários
    db = MongoClient(
        host=DB_HOST,
        port=DB_PORT
    )
    users = db[DB_NAME]['users']
    user = users.find_one({'username': username})
    return user['password']

def get_privileges(username):
    # Obtém a coleção de usuários
    db = MongoClient(
        host=DB_HOST,
        port=DB_PORT
    )
    users = db[DB_NAME]['users']
    user = users.find_one({'username': username})
    return user['level']
