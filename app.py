import requests
import json
import base64
from io import BytesIO
import io

from datetime import datetime

from flask_socketio import SocketIO, emit

from flask import Flask, flash, redirect, render_template, session, request, jsonify, send_file
from flask_session import Session

from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, before_first_request, check_for_sql, clear_session, generate_password, valid_email, get_distance

from google.oauth2 import id_token
from google.auth.transport import requests

from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

from bson import ObjectId

app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

socketio = SocketIO(app)


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
chats_collection = db["chats"]


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
                    "orders": 0,
                    "value_donated": 0,
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
        cur_type = business["type"] if business else None
        return render_template("business-home.html", user=user, business=business, type=cur_type)

    return render_template("business-home.html", user=user, business=None, type=None)


@app.route("/business-join", methods=["GET"])
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
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        businesses_html = render_template('business-list.html', businesses=businesses, user=user)
        return {'businesses_html': businesses_html}
    
    return render_template('business-join.html', user=user, business=business_id, businesses=businesses, type=None)


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


@app.route("/receiver-dashboard")
@login_required
def receiver_dashboard():
    """Receiver Dashboard"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    if session["business_id"] is None:
        return redirect('/business-join')

    business = businesses_collection.find_one({"_id": ObjectId(session["business_id"])})
    cur_type = business["type"] if business else None

    requests = []

    for request in business.get('requests', []):
        item = items_collection.find_one({"_id": request.get('item_id')})
        if item:
            bus_id = request.get('bus_id')
            if bus_id:
                provider = businesses_collection.find_one({"_id": bus_id})
                if provider:
                    requests.append({
                        "item_name": item.get('name'),
                        "provider_name": provider.get('name'),
                        "quantity": request.get('quantity'),
                        "provider_address": provider.get('address'),
                        "distance": get_distance(business.get('address'), provider.get('address')),
                        "status": request.get('status'),
                        "id": request.get('request_id')
                    })

    return render_template("receiver-dashboard.html", user=user, business=business, requests=requests, type=cur_type)


@app.route("/provider-dashboard")
@login_required
def provider_dashboard():
    """Business Dashboard"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    if session["business_id"] is None:
        return redirect('/business-join')

    business = businesses_collection.find_one({"_id": ObjectId(session["business_id"])})
    cur_type = business["type"] if business else None

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

    requests = []

    for request in business.get('requests', []):
        item = items_collection.find_one({"_id": request.get('item_id')})
        if item:
            bus_id = request.get('bus_id')
            if bus_id:
                foodbank = businesses_collection.find_one({"_id": bus_id})
                if foodbank:
                    requests.append({
                        "item_name": item.get('name'),
                        "food_bank_name": foodbank.get('name'),
                        "quantity": request.get('quantity'),
                        "food_bank_address": foodbank.get('address'),
                        "distance": get_distance(business.get('address'), foodbank.get('address')),
                        "status": request.get('status'),
                        "id": request.get('request_id')
                    })

    return render_template("provider-dashboard.html", user=user, business=business, applications=applications, members=members, requests=requests, type=cur_type)


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
    
    return redirect("/provider-dashboard")


@app.route('/remove-member/<user_id>', methods=['GET'])
def remove_member(user_id):
    """Manage applications for a business"""

    businesses_collection.update_one(
        {"_id": ObjectId(session["business_id"])},
        {"$pull": {"affiliated_users": ObjectId(user_id)}}
    )
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"business_id": None}}
    )
    flash("Member removed successfully!")
    
    return redirect("/provider-dashboard")


@app.route('/manage-requests/<decision>/<request_id>', methods=['GET'])
def manage_requests(decision, request_id):
    """Manage requests for a business"""

    request = businesses_collection.find_one(
        {"_id": ObjectId(session["business_id"])},
        {"requests": {"$elemMatch": {"request_id": ObjectId(request_id)}}}
    )

    request = request.get('requests', [])[0]
    item_id = request.get('item_id')
    quantity = request.get('quantity')

    if decision == 'accept':
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$set": {
                "requests.$[elem].status": "Accepted"
            }},
            array_filters=[{"elem.request_id": ObjectId(request_id)}]
        )
        flash("Request accepted successfully!")
    elif decision == 'decline':
        item_quantity = items_collection.find_one({"_id": item_id}).get('quantity', 0)
        items_collection.update_one(
            {"_id": item_id},
            {"$set": {"quantity": item_quantity+quantity}}
        )
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$pull": {"requests": {"request_id": ObjectId(request_id)}}}
        )
        flash("Request rejected successfully!")
    elif decision == 'confirm':
        item_name = items_collection.find_one({"_id": item_id}).get('name', 'Item')
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$push": {"history": {"request_id": ObjectId(request_id), "item": item_name, "qunatity": quantity, "status": "Delivered", "timestamp": datetime.now()}}}
        )
        item_cost = items_collection.find_one({"_id": item_id}).get('price', 0)
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$inc": {"value_donated": +quantity*item_cost, "orders": +1}}
        )
        businesses_collection.update_one(
            {"_id": ObjectId(session["business_id"])},
            {"$pull": {"requests": {"request_id": ObjectId(request_id)}}}
        )
        flash("Delivery confirmed!")
    else:
        flash("Invalid request!")
    
    return redirect("/provider-dashboard")


@app.route("/items", methods=["GET"])
@login_required
def items():
    """Display Food Item data"""
    
    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})
    
    cur_business_id = session["business_id"]

    cur_business = businesses_collection.find_one({"_id": ObjectId(cur_business_id)})
    cur_type = cur_business["type"] if cur_business else None

    if cur_type != "receiver":
        return redirect('/')
    
    query = request.args.get('query', '').lower()
    
    if query:
        items = list(items_collection.find({
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        }))
    else:
        items = list(items_collection.find())

    items = [item for item in items if item.get("quantity", 0) > 0]
    
    business_ids = {item.get("business_id") for item in items if item.get("business_id")}
    
    businesses = {b["_id"]: b for b in businesses_collection.find({"_id": {"$in": list(business_ids)}})}
    
    cur_address = cur_business.get("address", "No address found") if cur_business else "No address found"
    
    distance_cache = {}
    
    for item in items:
        business_id = item.get("business_id")
        business = businesses.get(business_id)
    
        if business:
            address = business.get("address", "No address found")
    
            if address == "No address found" or cur_address == "No address found":
                item["distance"] = None
            else:
                if address in distance_cache:
                    item["distance"] = distance_cache[address]
                else:
                    distance = get_distance(cur_address, address)
                    distance_cache[address] = distance
                    item["distance"] = distance
        else:
            item["distance"] = None
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        items_html  = render_template('items-list.html', items=items, user=user)
        return {'items_html': items_html}
    
    return render_template("items.html", user=user, items=items, business=cur_business_id, type=cur_type)


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
        
        quantity = int(quantity)
        price = float(price) if price else 0.0

        items_collection.insert_one({
            "name": item_name,
            "item_type": item_type,
            "quantity": int(quantity),
            "allergens": allergens,
            "tags": tags,
            "price": price,
            "description": description,
            "business_id": ObjectId(business_id)
        })

        flash("Item added successfully!", "success")
        return redirect('/provider-dashboard')
    
    flash("Failed to add item!")
    return redirect('/provider-dashboard')


@app.route("/request-item", methods=["GET"])
@login_required
def request_item():
    """Request Food Item"""

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    cur_business_id = session["business_id"]

    item_id = request.args.get('item_id')
    item_id = ObjectId(item_id)
    quantity = request.args.get('quantity')
    quantity = int(quantity)

    item = items_collection.find_one({"_id": item_id})
    
    items_collection.update_one(
        {"_id": item_id},
        {"$set": {"quantity": int(item.get("quantity"))-quantity}}
    )

    if not item:
        flash("Item not found.")
        return redirect('/items')

    business = businesses_collection.find_one({"_id": item["business_id"]})

    businesses_collection.update_one(
        {"_id": item["business_id"]},
        {"$push": {"requests": {"request_id": ObjectId(), "item_id": item_id, "bus_id": ObjectId(cur_business_id), "quantity": quantity, "status": "Pending"}}}
    )

    if not business:
        flash("Business not found.")
        return redirect('/items')

    flash(f"Request for {quantity} {item['name']}s submitted successfully!")
    return redirect('/items')


@app.route("/chat/<request_id>")
@login_required
def chat(request_id):
    """Chat Page"""

    chat = chats_collection.find_one({"request_id": ObjectId(request_id)})

    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    cur_business_id = session["business_id"]
    cur_type = businesses_collection.find_one({"_id": ObjectId(cur_business_id)})["type"]

    request = businesses_collection.find_one(
        {"_id": ObjectId(cur_business_id)},
        {"requests": {"$elemMatch": {"request_id": ObjectId(request_id)}}}
    )

    print(request_id)
    print(request)

    if chat:
        print("Chat found:", chat)
        if chat["users"][0] != ObjectId(cur_business_id) and chat["users"][1] != ObjectId(cur_business_id):
            print("User not authorized to view chat.")
            return redirect("/")
        
        user_1 = chat.get("users")[0]
        
        if cur_business_id == str(user_1):
            user_2 = chat.get("users")[1]
        else:
            user_2 = chat.get("users")[0]
            user_1 = chat.get("users")[1]

        user_1_info = businesses_collection.find_one(
            {"_id": user_1}
        )
        user_2_info = businesses_collection.find_one(
            {"_id": user_2}
        )
        item = items_collection.find_one({"_id": chat['item_id']})
        item_name = str(chat['quantity']) + " " + item['name']

        print("Line 633: ", user_1, user_2)
        messages = chat["messages"]
        return render_template("chat.html", user=user, messages=messages, request_id=request_id, user_1=user_1_info, user_2=user_2_info, item_name=item_name, type=cur_type)
    else:
        print("Chat not found.")

        chats_collection.insert_one({
            "request_id": ObjectId(request_id),
            "item_id": request['requests'][0]['item_id'],
            "quantity": request['requests'][0]['quantity'],
            "users": [ObjectId(cur_business_id), ObjectId(request['requests'][0]['bus_id'])],
            "messages": []
        })

    return redirect("/chat/"+request_id)

    chat = chats_collection.find_one({"request_id": ObjectId(request_id)})

    user_1 = chat.get("users")[0]

    if cur_business_id == user_1:
        user_2 = chat.get("users")[1]

    else:
        user_1 = chat.get("users")[1]
        user_2 = chat.get("users")[0]

    user_1_info = businesses_collection.find_one(
        {"_id": ObjectId(user_1)}
    )
    user_2_info = businesses_collection.find_one(
        {"_id": ObjectId(user_2)}
    )
    print("Line 655: ", user_1, user_2)
    
    return render_template("chat.html", user=user, messages=[], request_id=request_id, user_1=user_1_info, user_2=user_2_info)


@app.route("/send-message/<request_id>", methods=["POST"])
def send_message(request_id):
    
    user_id = session["user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"_id": 0, "hash": 0})

    cur_business_id = session["business_id"]

    message = request.form.get("message")

    if not message:
        return redirect("/chat/"+request_id)

    # Find the chat room
    chat = chats_collection.find_one({"request_id": ObjectId(request_id)})

    # Add the new message to the chat
    if chat:
        chats_collection.update_one(
            {"request_id": ObjectId(request_id)},
            {"$push": {"messages": {"sender": ObjectId(cur_business_id), "message": message, "timestamp": datetime.now()}}}
        )

    return redirect("/chat/"+request_id)


# @socketio.on('send_message')
# def handle_message(data):
#     user1_id = data['user1_id']
#     user2_id = data['user2_id']
#     message = data['message']

#     chat = chats_collection.find_one({
#         "users": {"$all": [ObjectId(user1_id), ObjectId(user2_id)]}
#     })

#     if chat:
#         chats_collection.update_one(
#             {"_id": chat["_id"]},
#             {"$push": {"messages": {"sender": ObjectId(user1_id), "message": message, "timestamp": datetime.now()}}}
#         )
#         emit('receive_message', {
#             'sender': user1_id,
#             'message': message,
#             'timestamp': datetime.now()
#         }, room=chat["_id"])


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
            user_id = insert_result.inserted_id
            session["business_id"] = str(business["_id"]) if business else None

            print("New user inserted with ID:", user_id)

        else:
            user_id = existing_user["_id"]
            business_id = existing_user["business_id"]
            session["business_id"] = str(business_id) if business_id else None

        session["user_id"] = str(user_id)

        return jsonify(success=True)

    except ValueError:
        print('Invalid token')
        return jsonify(success=False, error='Invalid token')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="3000", debug=True)
