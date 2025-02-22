import requests
import json
import base64
from io import BytesIO
import io
from PIL import Image

import sqlite3
from flask import Flask, flash, redirect, render_template, session, request, jsonify, send_file
from flask_session import Session

from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, before_first_request, check_for_sql, clear_session, generate_password, valid_email

from google.oauth2 import id_token
from google.auth.transport import requests

from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

from bson import ObjectId

app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


def get_mongodb_connection():
    """Create and return a new database connection."""
    with open('./static/cred.json', 'r') as file:
        uri = json.load(file)['mongoURI']
    client = MongoClient(uri, tlsAllowInvalidCertificates=True)
    try:
        client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
        return client["FoodBank"]
    except Exception as e:
        print(e)
        return None
    
db = get_mongodb_connection()

users_collection = db["users"]
businesses_collection = db["businesses"]
items_collection = db["items"]
# distributor_collection = db["distributors"]

def get_db_connection():
    """Create and return a new database connection."""
    conn = sqlite3.connect("static/sql/database.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row

    return conn


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.before_request
@before_first_request
def before_request():
    """Clear Session"""

    check_for_sql(app)

    # Calls function to redirect to login page only on app start
    clear_session(app)

    return


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Clear any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        error = None
        user_input = request.form.get("user")
        password = request.form.get("password")

        if not user_input:
            error = "Must provide email or username!"
        elif not password:
            error = "Must provide password!"
        else:
            user = users_collection.find_one({"$or": [{"username": user_input}, {"email": user_input}]})
            if not user or not check_password_hash(user["hash"], password):
                error = "Invalid username and/or password!"
            else:
                business = None
                if "business_id" in user:
                    business = businesses_collection.find_one({"_id": user["business_id"]})

                # Store user session
                session["user_id"] = str(user["_id"])
                session["business_id"] = str(business["_id"]) if business else None
                session["business_name"] = business["name"] if business else None
                return redirect("/")
            
        return render_template("login.html", error=error)
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        name = request.form.get('name')
        reg_id = request.form.get('reg_id')
        tax_id = request.form.get('tax_id')
        address = request.form.get('address')
        city = request.form.get('city')
        postal_code = request.form.get('postal-code')
        organizaion_type = request.form.get('type')
        food_safety_cert = request.form.get('food-safety')
        new_email = request.form.get("email")
        email_domain = request.form.get("email_domain")
        new_username = request.form.get("username")
        new_password = request.form.get("password")
        new_confirmation = request.form.get("confirmation")

        # Variable for storing error message
        error = None

        # Ensure email was submitted
        if not new_email:
            error = "Must provide email!"
        
        # Ensure correct format is followed
        elif valid_email(new_email) == False:
            error = "Invalid email provided!"

        # Ensure username is provided
        elif not new_username:
            error = "Must provide username!"

        # Ensure password was submitted
        elif not new_password:
            error = "Missing password!"

        # Ensure passwords match
        elif new_password != new_confirmation:
            error = "Passwords don't match!"

        # Ensure password is between 4 and 15 characters
        elif len(new_password) < 4 or len(new_password) > 15:
            error = "Password must be between 4 and 15 characters long!"

        # Ensure Business Registration Number is valid
        elif not reg_id.isdigit() or len(reg_id) < 1:
            error = "Invalid Business Registration Number!"
        
        # Ensure Tax Identification Number is valid
        elif not tax_id.isdigit() or len(tax_id) < 1:
            error = "Invalid Tax Identification Number!"

        # Ensure Postal Code is valid
        elif len(postal_code) != 6:
            error = "Postal Code should be 6 characters!"
        
        else:
            # Check if the username or email already exists in the database
            existing_user = users_collection.find_one({"$or": [{"username": new_username}, {"email": new_email}]})

            if existing_user:
                if existing_user["username"] == new_username:
                    error = "Username not available!"
                else:
                    error = "An account already exists with this email!"
                return render_template("register.html", error=error)
            else:

                new_business = {
                    "name": name,
                    "type": organizaion_type,
                    "address": address+", "+city+", "+postal_code,
                    "affiliate_users": [],
                    "email_domain": email_domain,
                    "rating": 75,
                    "reg_id": reg_id,
                    "tax_id": tax_id,
                    "fs_cert": True if food_safety_cert == 'yes' else False,
                }
                result = businesses_collection.insert_one(new_business)
                business_id = result.inserted_id

                hash_password = generate_password_hash(new_password, method='pbkdf2', salt_length=16)
                new_user = {
                    "username": name+" Admin",
                    "email": new_email,
                    "hash": hash_password,
                    "auto_generated": False,
                    "business_id": business_id,
                }
                user = users_collection.insert_one(new_user)
                user_id = user.inserted_id

                businesses_collection.update_one(
                    {"_id": business_id},
                    {"$push": {"affiliated_users": user_id}}
                )

                session["user_id"] = str(user_id)
                session["business_id"] = str(business_id)
                flash(f"Registered {name}!")
                return redirect("/")
            
        return render_template("register.html", error=error)

    else:
        return render_template("register.html")
        

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/")
@login_required
def home():
    """Main Page"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    business_id = session["business_id"]

    print(business_id)

    if business_id:
        business = businesses_collection.find_one({"_id": ObjectId(business_id)}, {"_id": 0})
        return render_template("business-home.html", user=user, business=business)

    return render_template("business-home.html", user=user, business=None)


@app.route("/business-join")
@login_required
def business_join():
    """Business Apply Page"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    business_id = session["business_id"]

    query = request.args.get('query', '').lower()
    
    if query:
        businesses = list(businesses_collection.find({
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        }))
    else:
        businesses = list(businesses_collection.find())
    
    return render_template('business-join.html', user=user, business=business_id, businesses=businesses)


@app.route('/apply/<business_id>', methods=['GET'])
@login_required
def apply_to_business(business_id):
    """Apply to a business"""    
    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    business = businesses_collection.find_one({"_id": ObjectId(business_id)})

    if not business:
        flash("Business not found.")
        return redirect('/business-join')

    if user_id in business.get('applicants', []):
        flash("You have already applied to this business.")
        return redirect('/business-join')

    businesses_collection.update_one(
        {"_id": ObjectId(business_id)},
        {"$push": {"applicants": ObjectId(user_id)}}
    )

    flash(f"Application to {business['name']} submitted successfully!")

    return redirect('/business-join')


@app.route("/business-dashboard")
@login_required
def business_dashboard():
    """Business Dashboard"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    if session["business_id"] is None:
        return redirect('/business-join')

    business = businesses_collection.find_one({"_id": ObjectId(session["business_id"])})

    # Fetch name and email for each applicant from the users collection
    applications = []
    
    for applicant_id in business.get('applicants', []):
        user = users_collection.find_one({"_id": ObjectId(applicant_id)})
        if user:
            applications.append({
                "name": user.get('username'),
                "email": user.get('email'),
                "status": "Pending",
                "id": applicant_id
            })

    members = []

    for applicant_id in business.get('affiliated_users', []):
        user = users_collection.find_one({"_id": ObjectId(applicant_id)})
        if user:
            members.append({
                "name": user.get('username'),
                "email": user.get('email'),
                "id": applicant_id
            })

    return render_template("business-dashboard.html", user=user, business=business, applications=applications, members=members)


@app.route('/manage-applications/<decision>/<user_id>', methods=['GET'])
def manage_applications(decision, user_id):
    """Manage applications for a business"""

    if decision == 'accept':
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$pull": {"applicants": ObjectId(user_id)}}
        )
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$push": {"affiliated_users": ObjectId(user_id)}}
        )
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"business_id": ObjectId(session["business_id"])}}
        )
        flash("Application accepted successfully!")
    else:
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$pull": {"applicants": ObjectId(user_id)}}
        )
        flash("Application rejected successfully!")
    
    return redirect("/business-dashboard")


@app.route("/items")
@login_required
def items():
    """Display Food Item data"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    business_id = session["business_id"]

    query = request.args.get('query', '').lower()
    
    # Search the items collection based on the query
    if query:
        items = list(items_collection.find({
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        }))
    else:
        items = list(items_collection.find())
    
    return render_template("items.html", user=user, items=items, business=business_id)


@app.route("/add-item", methods=["POST"])
@login_required
def add_item():
    """Add Food Item"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})
    
    if session["business_id"] is None:
        return redirect('/business-join')

    business_id = session["business_id"]
    print(business_id)

    if request.method == "POST":

        item_name = request.form.get("item_name")
        item_type = request.form.get("item_type")
        quantity = request.form.get("quantity")
        allergens = request.form.get("allergens").split(",")
        tags = request.form.get("tags").split(",")
        price = request.form.get("price")
        description = request.form.get("description")
        business_id = request.form.get("business_id")
        
        # Ensure quantity and price are numbers
        quantity = int(quantity)
        price = float(price) if price else 0.0

        # Insert the item into the items collection
        items_collection.insert_one({
            "name": item_name,
            "item_type": item_type,
            "quantity": quantity,
            "allergens": allergens,
            "tags": tags,
            "price": price,
            "description": description,
            "business_id": business_id
        })

        flash("Item added successfully!", "success")
        return redirect('/business-dashboard')
    
    flash("Failed to add item!")
    return redirect('/business-dashboard')

@app.route("/credit")
@login_required
def credit():
    """Display Government Credits & Tax Benefits"""

    conn = get_db_connection()
    db = conn.cursor()

    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?;", (user_id,)).fetchone()

    
    conn.close()

    return render_template("credit.html",  user=user)


@app.route("/settings", methods=["GET", "POST"] )
@login_required
def settings():
    """Settings Page"""

    conn = get_db_connection()
    db = conn.cursor()

    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?;", (user_id,)).fetchone()

    generated = user['auto_generated']

    if request.method == "POST":

        error = None
        success = None

        new_username = request.form.get("username")
        new_email = request.form.get("email")
        display = request.form.get("display")
       
        if generated:
            set_password = request.form.get("set-password")
        else:
            new_password = request.form.get("new-password")
            current_password = request.form.get("current-password")

        existing_usernames = db.execute("SELECT * FROM users WHERE username = ? AND NOT id = ?", (new_username, user['id']))
        existing_emails = db.execute("SELECT * FROM users WHERE email = ? AND NOT id = ?", (new_email, user['id']))

        hash = db.execute("SELECT hash FROM users WHERE id = ?", user['id'])[0]['hash']

        if not new_username or not new_email:
            error = "Must fill all fields!"
            conn.close()
            return render_template("settings.html",  user=user, error=error)
        
        elif len(existing_usernames) != 0:
            error = "Username already taken!"
            conn.close()
            return render_template("settings.html",  user=user, error=error)

        elif len(existing_emails) != 0:
            error = "Account already exists for specified email!"
            conn.close()
            return render_template("settings.html",  user=user, error=error)

        elif valid_email(new_email) == False:
            error = "Invalid email provided!"
            conn.close()
            return render_template("settings.html",  user=user, error=error)

        elif generated:

            if len(set_password) < 4 or len(set_password) > 15:
                error = "Password must be between 4 and 15 characters long!"
                conn.close()
                return render_template("settings.html",  user=user, error=error)

        elif not generated:

            if not current_password:
                error = "Current password not provided!"
                conn.close()
                return render_template("settings.html",  user=user, error=error)
            
            elif not check_password_hash(hash, current_password):
                error = "Current password incorrect!"
                conn.close()
                return render_template("settings.html",  user=user, error=error)

            elif display == "flex":

                if new_username == user['username'] and new_email == user['email'] and check_password_hash(hash, current_password) and (not new_password or new_password == current_password):
                    error = "Account Details have not changed!"
                    print("all")
                    conn.close()
                    return render_template("settings.html",  user=user, error=error)
                
                elif not new_password:
                    error = "New password not set!"
                    conn.close()
                    return render_template("settings.html",  user=user, error=error)
                
                elif len(new_password) < 4 or len(new_password) > 15:
                    error = "New password must be between 4 and 15 characters long!"
                    conn.close()
                    return render_template("settings.html",  user=user, error=error)

        if generated:

            if new_username == user['username'] and new_email != user['email']:
                db.execute("UPDATE users SET email = ? WHERE id = ?;", new_email, user['id'])
                success = "Email succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            elif new_username != user['username'] and new_email == user['email']:
                db.execute("UPDATE users SET username = ? WHERE id = ?;", new_username, user['id'])
                success = "Username succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            else:
                hash = generate_password_hash(set_password, method='pbkdf2', salt_length=16)
                db.execute("UPDATE users SET hash = ?;", hash)
                db.execute("UPDATE users SET auto_generated = ?;", False)
                success = "Password succesfully set!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)

        elif not generated:

            if new_username == user['username'] and new_email != user['email'] and check_password_hash(hash, current_password) and display == "none":
                db.execute("UPDATE users SET email = ? WHERE id = ?;", new_email, user['id'])
                success = "Email succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            elif new_username != user['username'] and new_email == user['email'] and check_password_hash(hash, current_password) and display == "none":
                db.execute("UPDATE users SET username = ? WHERE id = ?;", new_username, user['id'])
                success = "Username succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            elif new_username != user['username'] and new_email != user['email'] and check_password_hash(hash, current_password) and display == "none":
                db.execute("UPDATE users SET username = ?, email = ? WHERE id = ?;", new_username, new_email, user['id'])
                success = "Email & Username succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            elif new_username == user['username'] and new_email == user['email'] and new_password != current_password and check_password_hash(hash, current_password) and new_password and display == "flex":
                hash = generate_password_hash(new_password, method='pbkdf2', salt_length=16)
                db.execute("UPDATE users SET hash = ?;", hash)
                success = "Password succesfully updated!"
                conn.close()
                return render_template("settings.html",  user=user, success=success)
            
            else:
                error = "Password must be updated alone!"
                conn.close()
                return render_template("settings.html",  user=user, error=error)

        conn.close()
        return render_template("settings.html",  user=user)

    conn.close()
    return render_template("settings.html",  user=user, generated=generated)


@app.route("/about")
@login_required
def about():
    """About Page"""

    conn = get_db_connection()
    db = conn.cursor()

    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?;", (user_id,)).fetchone()

    conn.close()
    return render_template("about.html",  user=user)


@app.route('/google-signin', methods=['POST'])
def google_signin():

    with open('./static/cred.json', 'r') as file:
        data = json.load(file)['clientID']
        
    YOUR_CLIENT_ID = data

    id_token_received = request.form['id_token']

    try:

        idinfo = id_token.verify_oauth2_token(id_token_received, requests.Request(), YOUR_CLIENT_ID)

        user_id = idinfo['sub']
        user_name = idinfo['name']
        user_email = idinfo['email']

        existing_user = users_collection.find_one({"email": user_email})

        if not existing_user:
            # Create new user
            email_domain = user_email.split("@")[-1]
            business = businesses_collection.find_one({"email_domain": email_domain})
            
            password = generate_password(12)
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

            new_user = {
                "email": user_email,
                "username": user_name,
                "hash": hashed_password,
                "auto_generated": True,
                "business_id": business["_id"] if business else None
            }

            insert_result = users_collection.insert_one(new_user)
            user_id = insert_result.inserted_id  # Get the generated _id
            session["business_id"] = str(business["_id"]) if business else None

            print("New user inserted with ID:", user_id)

        else:
            user_id = existing_user["_id"]  # Retrieve existing user's _id
            business_id = existing_user["business_id"]
            session["business_id"] = str(business_id) if business_id else None

        # Store user ID in session
        session["user_id"] = str(user_id)  # Convert ObjectId to string for session storage

        return jsonify(success=True)

    except ValueError:
        print('Invalid token')
        return jsonify(success=False, error='Invalid token')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="3000", debug=True)
