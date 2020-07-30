from sqlalchemy import BigInteger, Column, String, Unicode, Integer, JSON
from sqlalchemy.types import TypeDecorator, Text
from base64 import decodebytes
from base64 import encodebytes
import json
from tornado.log import app_log
from tornado_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
db.Model.log = app_log

class User(db.Model):
    __tablename__ = 'users'

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    username = Column(Unicode(255), unique=True, nullable=False)
    auth_state = Column(JSON)