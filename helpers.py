import secrets
import string
import re
import json
import requests
import os

from dotenv import load_dotenv
load_dotenv()

from opencage.geocoder import OpenCageGeocode
from pprint import pprint

from datetime import datetime, timedelta

from functools import wraps
from flask import redirect, session, request, current_app


# Decorator to require login
def login_required(f):
    """Decorate routes to require login"""

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if session.get("user_id") is None:

            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function


# Decorator to execute before first request
def before_first_request(f):
    """Decorate routes to execute before first request"""

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if not current_app.config.get("BEFORE_FIRST_REQUEST"):

            return f(*args, **kwargs)

            current_app.config["BEFORE_FIRST_REQUEST"] = True

    return decorated_function


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


# Checks for correct email regex
def valid_email(email):
    emailRegex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    return re.match(emailRegex, email) is not None


# Calculates distance between two locations
def get_distance(origin, destination):

    # with open('./static/cred.json', 'r') as file:
    #     api_key = json.load(file)['mapsAPI']

    api_key = os.getenv("MAPS_API")

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


# Gets coordinates of a location
def get_coordinates(address):

    # with open('./static/cred.json', 'r') as file:
    #     api_key = json.load(file)['openCageAPI']

    api_key = os.getenv("OPENCAGE_API")

    geocoder = OpenCageGeocode(api_key)

    results = geocoder.geocode(address)

    if results and len(results):
        return results[0]['geometry']
    else:
        return None
    

# Converts a datetime object to a human-readable relative time format
def time_ago(timestamp):
    """Convert a datetime object to a human-readable relative time format."""

    now = datetime.now()
    
    diff = now - timestamp
    
    if diff < timedelta(minutes=1):
        return "Just now"
    elif diff < timedelta(hours=1):
        return f"{diff.seconds // 60} minutes ago"
    elif diff < timedelta(days=1):
        return f"{diff.seconds // 3600} hours ago"
    elif diff < timedelta(weeks=1):
        return f"{diff.days} days ago"
    else:
        return f"{diff.days // 7} weeks ago"