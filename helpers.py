import os
import secrets
import string
import re
import json
import cohere
import requests

from opencage.geocoder import OpenCageGeocode
from pprint import pprint

from functools import wraps
from flask import redirect, session, request, current_app

import os.path
import sqlite3

import numpy as np
import os

def login_required(f):
    """Decorate routes to require login"""

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if session.get("user_id") is None:

            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function


def before_first_request(f):
    """Decorate routes to execute before first request"""

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if not current_app.config.get("BEFORE_FIRST_REQUEST"):

            return f(*args, **kwargs)

            current_app.config["BEFORE_FIRST_REQUEST"] = True

    return decorated_function

# Runs SQL from file
def run_sql(sql_file):
    """Runs SQL Commands from a file"""
    db_path = "./static/sql/database.db"
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        with open('./static/sql/' + sql_file, 'r') as file:
            sql_commands = file.read().split(';')
        for command in sql_commands:
            if command.strip():
                cursor.execute(command)
        conn.commit()
    except sqlite3.Error as e:
        print(f"SQL error: {e}")
    finally:
        conn.close()

# Creates SQL structures if they don't exist
def check_for_sql(app):
    """Ensures SQL structures exist"""
    db_path = "./static/sql/database.db"
    if not app.config.get("BEFORE_CHECK_EXECUTED"):
        if not os.path.exists(db_path):
            run_sql('schema.sql')
        app.config["BEFORE_CHECK_EXECUTED"] = True

# Clears local flask sessions
def clear_session(app):
    """Clears Session and redirects to login page"""

    if not app.config.get("BEFORE_REQUEST_EXECUTED"):

        if request.endpoint != 'static' and request.endpoint != 'login':

            session.clear()

            return redirect("/login")

        app.config["BEFORE_REQUEST_EXECUTED"] = True

# Generates a random password
def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

#Checks for correct email regex
def valid_email(email):
    emailRegex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    return re.match(emailRegex, email) is not None


def get_distance(origin, destination):

    with open('./static/cred.json', 'r') as file:
        api_key = json.load(file)['mapsAPI']

    base_url = "https://maps.googleapis.com/maps/api/distancematrix/json"
    params = {
        "origins": origin,
        "destinations": destination,
        "key": api_key
    }

    response = requests.get(base_url, params=params)
    data = response.json()

    if data["status"] == "OK":
        distance = data["rows"][0]["elements"][0]["distance"]["text"]
        return distance
    else:
        return "Error: Unable to fetch distance"


def get_coordinates(address):

    with open('./static/cred.json', 'r') as file:
        api_key = json.load(file)['openCageAPI']

    geocoder = OpenCageGeocode(api_key)

    results = geocoder.geocode(address)

    if results and len(results):
        return results[0]['geometry']
    else:
        return None