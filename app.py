from flask import Flask, render_template, request, redirect, url_for, flash, jsonify,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import datetime,timedelta
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from functools import wraps
from flask_cors import CORS

import json  
import sys
import os


sys.path.append("/home/smartq")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///canteen.db'
app.config['JWT_SECRET_KEY'] = '8590659295ysmartq'
app.config['SECRET_KEY'] = '8590659295ysmartq'
app.config['UPLOAD_FOLDER'] = "static/uploads"

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, origins=["*"])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fetch admin credentials from environment variables
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


# Models--------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    available = db.Column(db.Boolean, default=True)
    rating = db.Column(db.Float, default=1)
    image_url = db.Column(db.String(255), nullable=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    order_no = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)  
    items = db.Column(db.Text, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
# Models--------------------------------------------------------------
# db creation and admin initialisation--------------------------------------------------------------

with app.app_context():
    db.create_all()
    if not User.query.filter_by(email=ADMIN_USERNAME).first():
        hashed_password = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8') 
        admin = User(email=ADMIN_USERNAME, password_hash=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")


# db creation and admin initialisation--------------------------------------------------------------

# user views--------------------------------------------------------------

#new user registration
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    existing_user = User.query.filter_by(email=data['email']).first()

    if existing_user:
        return jsonify({"error": "Email already exists"}), 400  

    hashed_pw = generate_password_hash(data['password'])  
    new_user = User(email=data['email'], password_hash=hashed_pw)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "Registration Success!"}), 201


#user login view
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password_hash, password):
        token = create_access_token(identity=json.dumps({"id": user.id, "email": user.email}), expires_delta=timedelta(hours=1))
        return jsonify({"message": "Login successful", "token": token})

    return jsonify({"error": "Invalid credentials"}), 401

#view all avaialable menu items on userside
@app.route('/menu', methods=['GET'])
def get_menu():
    menu_items = MenuItem.query.filter_by(available=True).all()
    return jsonify([
        {
            "id": item.id,
            "name": item.name,
            "price": item.price,
            "rating": item.rating,
            "image_url": item.image_url
        } for item in menu_items
    ])

#creating new order from user
@app.route('/user/order', methods=['POST'])
@jwt_required()
def place_order():
    current_user = json.loads(get_jwt_identity())  
    user_id = current_user.get('id')
    email = current_user.get('email')

    data = request.json
    
    new_order = Booking(
        
        user_id=user_id,
        email=email,
        order_no=data['payment_id'],
        items=data['items'],
        total_amount=float(data['total_amount']),
        date_time=datetime.utcnow()
    )
    
    db.session.add(new_order)
    db.session.commit()
    return jsonify({"message": "Order placed successfully!", "order_no": new_order.order_no})


#fetching selected user all orders
@app.route('/user/orders', methods=['GET'])
@jwt_required()
def user_orders():
    current_user = get_jwt_identity()
    if isinstance(current_user, str):  
        current_user = json.loads(current_user)

    orders = Booking.query.filter_by(user_id=current_user['id']).order_by(Booking.date_time.desc()).all()

    return jsonify([
        {
            "id": o.id,
            "order_no": o.order_no,
            "user_id": o.user_id,
            "email": o.email,
            "items": o.items,
            "total_amount": float(o.total_amount),
            "status": o.status,
            "date_time": o.date_time.strftime('%Y-%m-%d %H:%M:%S')
        } for o in orders
    ])



#user order cancelling view
@app.route('/user/orders/<int:order_id>', methods=['DELETE'])
@jwt_required()
def cancel_order(order_id):
    current_user = get_jwt_identity() 
    if isinstance(current_user, str):  
        current_user = json.loads(current_user) 

    order = Booking.query.filter_by(id=order_id, user_id=current_user['id']).first_or_404(
        description="Order not found or unauthorized"
    )

    db.session.delete(order)
    db.session.commit()
    return jsonify({"message": "Order canceled successfully!"})

# user views--------------------------------------------------------------

# admin views--------------------------------------------------------------

#admin required custom view for session checking
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash("Please log in as admin first.", "danger")
            return redirect(url_for('admin_login'))
        return func(*args, **kwargs)
    return wrapper



#admin logout view
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('admin_login'))



#admin login view
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = User.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password_hash, password):
            session['admin_logged_in'] = True
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template('admin_login.html')



# Admin Dashboard Route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    menu_items = MenuItem.query.all()
    return render_template('admin_dashboard.html', menu_items=menu_items)



#admin adding new item on menu view
@app.route('/admin/add_menu', methods=['GET', 'POST'])
def admin_add_menu():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        available = 'available' in request.form

        image_url = None  

        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                filename = secure_filename(image.filename)
                upload_folder = app.config['UPLOAD_FOLDER']

                os.makedirs(upload_folder, exist_ok=True)

                image_path = os.path.join(upload_folder, filename)
                image.save(image_path)
                image_url = f"/static/uploads/{filename}"

        new_item = MenuItem(name=name, price=price, image_url=image_url, available=available)
        db.session.add(new_item)
        db.session.commit()

        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_menu.html')


#admin edit menu form rendering with given item details
@app.route('/menu/edit/<int:item_id>')
def edit_menu_page(item_id):

    item = MenuItem.query.get_or_404(item_id)
    return render_template("update_menu.html", item=item)



#admin add new item on menu
@app.route('/menu/<int:item_id>/update', methods=['POST'])
def update_menu(item_id):

    item = MenuItem.query.get(item_id)
    if not item:
        return jsonify({'error': 'Item not found'}), 404

    # Update form fields
    item.name = request.form.get('name', item.name)
    item.price = request.form.get('price', item.price)
    item.available = bool(request.form.get('available')) 

    # Handle Image Upload
    if 'image' in request.files:
        image = request.files['image']
        if image.filename:
            filename = secure_filename(image.filename)
            upload_folder = app.config['UPLOAD_FOLDER']

            os.makedirs(upload_folder, exist_ok=True)

            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)

            item.image_url = f"/static/uploads/{filename}"

    db.session.commit()
    return redirect(url_for('admin_dashboard'))




#admin deleting item from menu
@app.route('/admin/menu/<int:item_id>/delete', methods=['POST'])
@admin_required
def delete_menu_item(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))



#admin view for showing all bookings or orders
@app.route('/admin/orders')
@admin_required
def orders():
    orders = Booking.query.all()
    return render_template('admin_orders.html', orders=orders)


#admin order status updating view
@app.route('/admin/orders/<int:order_id>/update', methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Booking.query.get(order_id)
    if order:
        data = request.form
        order.status = data['status']
        db.session.commit()
    return redirect(url_for('orders'))


# admin views-------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
