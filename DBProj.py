__author__ = 'Leewiz'
import sys
import sqlite3
import flask
from contextlib import contextmanager

app = flask.Flask(__name__)
app.config.from_pyfile('settings.py')
