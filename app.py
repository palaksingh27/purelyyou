import os
import logging
import re
import uuid
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
import json
import base64
import numpy as np
import cv2
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
try:
    from email_validator import validate_email, EmailNotValidError
except ImportError:
    pass  # We'll handle this gracefully if the package is missing

from utils.facial_analysis import analyze_face
from utils.product_recommender import get_recommendations

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize Flask app
db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///beauty_app.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize CORS, CSRF protection, and database
CORS(app)
csrf = CSRFProtect(app)
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Add CSRF token to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=lambda: '<input type="hidden" name="csrf_token" value="{0}">'.format(request.cookies.get('csrf_token', '')))

# Import models before creating tables to ensure they're registered
with app.app_context():
    import models  # noqa: F401

# Main route that displays the homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route to display all products
@app.route('/products')
def products():
    from models import Product
    all_products = Product.query.all()
    return render_template('products.html', products=all_products)

# Route for selfie analysis page
@app.route('/selfie-analysis')
@app.route('/selfie_analysis')  # Adding an alternate route to handle both formats
def selfie_analysis():
    return render_template('selfie_analysis.html')

# Route for skincare tips page
# Skincare tips route removed as per user request

# API endpoint to process selfie and return recommendations
@app.route('/api/analyze-selfie', methods=['POST'])
@csrf.exempt  # Exempt this endpoint from CSRF protection for API access
def analyze_selfie_endpoint():
    try:
        logger.info("Selfie analysis request received")
        data = request.get_json()
        if not data or 'image' not in data:
            logger.error("No image data provided in request")
            return jsonify({'error': 'No image data provided'}), 400
        
        # ---------- Image Decoding ----------
        logger.info("Image data received, proceeding with analysis")
        # Decode the base64 image
        try:
            if ',' in data['image']:
                image_data = data['image'].split(',')[1]
            else:
                image_data = data['image']
                
            logger.info("Base64 image decoded")
            image_bytes = base64.b64decode(image_data)
            np_arr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            
            if img is None:
                logger.error("Image could not be decoded properly")
                return jsonify({'error': 'Failed to decode image'}), 400
                
            logger.info(f"Image decoded successfully, shape: {img.shape}")
        except Exception as e:
            logger.error(f"Error decoding image: {str(e)}")
            return jsonify({'error': f'Error decoding image: {str(e)}'}), 400
        
        # ---------- Facial Analysis ----------
# Analyze the face
        logger.info("Starting facial analysis")
        facial_features = analyze_face(img)
        # We always get results now, even if face detection fails
        logger.info(f"Facial features detected: {facial_features}")
        
        # ---------- Recommendation Engine ----------
# Get product recommendations based on facial features
        from models import Product
        products = Product.query.all()
        logger.info(f"Found {len(products)} products to analyze for recommendations")
        
        recommendations = get_recommendations(facial_features, products)
        logger.info(f"Generated {len(recommendations)} product recommendations")
        
        # Store recommendations in session
        session['recommendations'] = [p.to_dict() for p in recommendations]
        
        return jsonify({
            'success': True,
            'features': facial_features,
            'recommendations': [p.to_dict() for p in recommendations]
        })
    except Exception as e:
        logger.error(f"Error processing selfie: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# Shopping cart routes
@app.route('/cart')
def view_cart():
    # Get cart items from session
    cart = session.get('cart', [])
    total = sum(item.get('price', 0) * item.get('quantity', 0) for item in cart)
    return render_template('cart.html', cart=cart, total=total)

@app.route('/api/cart/add', methods=['POST'])
@csrf.exempt  # Exempt from CSRF protection for API access
def add_to_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
    
    # Get the product
    from models import Product
    product = Product.query.get(product_id)
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    # Initialize cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = []
    
    # Check if product is already in cart
    cart = session['cart']
    for item in cart:
        if item.get('id') == product_id:
            item['quantity'] = item.get('quantity', 0) + 1
            session.modified = True
            return jsonify({'success': True, 'cart': cart})
    
    # Add new product to cart
    cart.append({
        'id': product.id,
        'name': product.name,
        'price': float(product.price),
        'image_url': product.image_url,
        'quantity': 1
    })
    
    session.modified = True
    return jsonify({'success': True, 'cart': cart})

@app.route('/api/cart/remove', methods=['POST'])
@csrf.exempt  # Exempt from CSRF protection for API access
def remove_from_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    
    if not product_id or 'cart' not in session:
        return jsonify({'error': 'Invalid request'}), 400
    
    cart = session['cart']
    session['cart'] = [item for item in cart if item.get('id') != product_id]
    session.modified = True
    
    return jsonify({'success': True, 'cart': session['cart']})

@app.route('/api/cart/update', methods=['POST'])
@csrf.exempt  # Exempt from CSRF protection for API access
def update_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 0)
    
    if not product_id or 'cart' not in session or quantity < 0:
        return jsonify({'error': 'Invalid request'}), 400
    
    cart = session['cart']
    for item in cart:
        if item.get('id') == product_id:
            if quantity == 0:
                cart.remove(item)
            else:
                item['quantity'] = quantity
            break
    
    session.modified = True
    return jsonify({'success': True, 'cart': cart})

# User authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Create a form object for CSRF protection
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        # Input validation
        if not email or not password:
            return render_template('login.html', error='Please provide both email and password', form=form)
        
        # Check if user exists
        from models import User
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            # Login user with Flask-Login
            login_user(user, remember=remember)
            
            # Store additional user info in session
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            # If user has skin data, store it in session
            if user.skin_type and user.skin_tone:
                session['skin_data'] = {
                    'skin_type': user.skin_type,
                    'skin_tone': user.skin_tone,
                    'concerns': user.get_concerns()
                }
            
            # Log success
            logger.info(f"User {user.username} logged in successfully")
            
            # Redirect to homepage or next URL
            next_page = request.args.get('next', '/')
            # Make sure the next page is safe (not a malicious redirect)
            if not next_page.startswith('/'):
                next_page = '/'
            return redirect(next_page)
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            return render_template('login.html', error='Invalid email or password', form=form)
    elif request.method == 'POST':
        # This will catch CSRF validation failures
        logger.error("Form validation failed - likely CSRF token issue")
        return render_template('login.html', error='Security validation failed. Please try again.', form=form)
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Create a form object for CSRF protection
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        newsletter = 'newsletter' in request.form
        
        # Input validation
        if not username or not email or not password or not confirm_password:
            return render_template('register.html', error='All fields are required', form=form)
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match', form=form)
        
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters long', form=form)
        
        # Check if user already exists
        from models import User
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists', form=form)
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already exists', form=form)
        
        # Create new user
        try:
            new_user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                receive_newsletter=newsletter
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            # Log user in automatically with Flask-Login
            login_user(new_user)
            
            # Store additional info in session
            session['username'] = new_user.username
            session['is_admin'] = False
            
            logger.info(f"New user registered: {username} ({email})")
            
            flash('Your account has been created successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return render_template('register.html', error='An error occurred. Please try again.', form=form)
    elif request.method == 'POST':
        # This will catch CSRF validation failures
        logger.error("Registration form validation failed - likely CSRF token issue")
        return render_template('register.html', error='Security validation failed. Please try again.', form=form)
    
    return render_template('register.html', form=form)

# Setup for password reset
def get_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except (SignatureExpired, BadSignature):
        return None
    return email

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # Create a form object for CSRF protection
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        email = request.form.get('email')
        
        if not email:
            return render_template('forgot_password.html', error='Please provide your email address', form=form)
        
        # Check if user exists
        from models import User
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Don't reveal if email exists
            return render_template('forgot_password.html', success='If your email is registered, you will receive password reset instructions.', form=form)
        
        # Generate reset token
        token = get_reset_token(email)
        
        # For development purposes, we'll display the reset link
        # In production, this would be sent via email
        reset_link = url_for('reset_password', token=token, _external=True)
        logger.info(f"Password reset link: {reset_link}")
        
        return render_template('forgot_password.html', success='If your email is registered, you will receive password reset instructions.', form=form)
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Create a form object for CSRF protection
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    # Verify the token
    email = verify_reset_token(token)
    if not email:
        return render_template('forgot_password.html', error='Invalid or expired password reset link. Please try again.', form=form)
    
    if request.method == 'POST' and form.validate_on_submit():
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Input validation
        if not password or not confirm_password:
            return render_template('reset_password.html', error='Please fill in all fields', token=token, form=form)
        
        if password != confirm_password:
            return render_template('reset_password.html', error='Passwords do not match', token=token, form=form)
        
        if len(password) < 8:
            return render_template('reset_password.html', error='Password must be at least 8 characters long', token=token, form=form)
        
        # Update user's password
        from models import User
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return render_template('forgot_password.html', error='Invalid account. Please try again.', form=form)
        
        user.set_password(password)
        db.session.commit()
        
        # Redirect to login with success message
        flash('Your password has been updated successfully. Please login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token, form=form)

@app.route('/logout')
def logout():
    # Flask-Login logout
    logout_user()
    
    # Remove any additional user info from session
    session.pop('username', None)
    session.pop('skin_data', None)
    session.pop('is_admin', None)
    
    # Flash a message to the user
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Initialize the database with sample products
def initialize_database():
    # Import models first
    from models import Product, User
    
    # Create tables
    db.create_all()
    
    # Create admin user if none exists
    admin_email = 'admin@purelyyou.com'
    if not User.query.filter_by(email=admin_email).first():
        admin_user = User(
            username='admin',
            email=admin_email,
            first_name='Admin',
            last_name='User',
            is_admin=True,
            receive_newsletter=False
        )
        admin_user.set_password('adminpassword')
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Admin user created")
    
    # Check if products exist, if not create sample products
    if Product.query.count() == 0:
        sample_products = [
            Product(
                name="Hydrating Face Moisturizer",
                description="A lightweight formula that deeply hydrates dry skin.",
                price=24.99,
                category="moisturizer",
                image_url="https://images.unsplash.com/photo-1556227834-09f1de7a7d14?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8c2tpbmNhcmV8fHx8fHwxNjgwMTIzNDU2&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["dry", "normal"],
                concerns=["dryness", "aging"]
            ),
            Product(
                name="Oil Control Serum",
                description="Regulates sebum production and minimizes pores.",
                price=32.99,
                category="serum",
                image_url="https://images.unsplash.com/photo-1611080626919-7cf5a9dbab12?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8c2VydW18fHx8fHwxNjgwMTIzNTEy&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["oily", "combination"],
                concerns=["oiliness", "acne"]
            ),
            Product(
                name="Gentle Exfoliating Scrub",
                description="Removes dead skin cells without irritation.",
                price=18.50,
                category="exfoliant",
                image_url="https://images.unsplash.com/photo-1608248597279-f99d160bfcbc?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8ZXhmb2xpYXRlfHx8fHx8MTY4MDEyMzU2OQ&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["texture", "dullness"]
            ),
            Product(
                name="Brightening Vitamin C Serum",
                description="Fades dark spots and enhances skin radiance.",
                price=45.00,
                category="serum",
                image_url="https://images.unsplash.com/photo-1620916566398-39f1143ab7be?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8c2VydW18fHx8fHwxNjgwMTIzNjI4&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["hyperpigmentation", "dullness"]
            ),
            Product(
                name="Soothing Aloe Gel",
                description="Calms irritated or sensitive skin.",
                price=15.99,
                category="treatment",
                image_url="https://images.unsplash.com/photo-1626881255758-a3871379ca49?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8YWxvZXx8fHx8fDE2ODAxMjM2ODg&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["sensitive", "all"],
                concerns=["redness", "irritation"]
            ),
            Product(
                name="Anti-Aging Night Cream",
                description="Reduces fine lines and wrinkles while you sleep.",
                price=58.00,
                category="moisturizer",
                image_url="https://images.unsplash.com/photo-1600428877878-1a0ff561d1ec?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8bmlnaHQgY3JlYW18fHx8fHwxNjgwMTIzNzQz&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["mature", "normal", "dry"],
                concerns=["aging", "wrinkles"]
            ),
            Product(
                name="Hyaluronic Acid Toner",
                description="Adds hydration while balancing skin pH.",
                price=22.50,
                category="toner",
                image_url="https://images.unsplash.com/photo-1601049329028-574ea58fba38?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8dG9uZXJ8fHx8fHwxNjgwMTIzNzk0&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["dryness", "dullness"]
            ),
            Product(
                name="Clay Purifying Mask",
                description="Draws out impurities and excess oil.",
                price=19.99,
                category="mask",
                image_url="https://images.unsplash.com/photo-1571875257727-256c39da42af?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8Y2xheSBtYXNrfHx8fHx8MTY4MDEyMzg0OQ&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["oily", "combination"],
                concerns=["acne", "oiliness"]
            ),
            Product(
                name="SPF 50 Facial Sunscreen",
                description="Protects skin from harmful UV rays without clogging pores.",
                price=26.00,
                category="suncare",
                image_url="https://images.unsplash.com/photo-1566958769143-c363d9a4b608?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8c3Vuc2NyZWVufHx8fHx8MTY4MDEyMzkwMw&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["sun protection", "aging"]
            ),
            Product(
                name="Lip Plumping Balm",
                description="Hydrates and adds natural volume to lips.",
                price=16.99,
                category="lip care",
                image_url="https://images.unsplash.com/photo-1596462502278-27bfdc403348?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8bGlwIGJhbG18fHx8fHwxNjgwMTIzOTUz&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["dryness", "volume"]
            ),
            # Adding new products
            Product(
                name="Advanced Retinol Complex",
                description="Powerful anti-aging formula with encapsulated retinol for smoother skin.",
                price=65.99,
                category="treatment",
                image_url="https://images.unsplash.com/photo-1576426863848-c21f53c60b19?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8c2tpbmNhcmV8fHx8fHwxNjgwMTI0MTAw&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["mature", "normal", "dry"],
                concerns=["aging", "wrinkles", "texture"]
            ),
            Product(
                name="Enzyme Exfoliation Powder",
                description="Gentle rice-based enzyme powder that activates with water for daily exfoliation.",
                price=34.50,
                category="exfoliant",
                image_url="https://images.unsplash.com/photo-1556760544-74068565f05c?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8cG93ZGVyfHx8fHx8MTY4MDEyNDE2NA&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["sensitive", "all"],
                concerns=["texture", "dullness", "sensitivity"]
            ),
            Product(
                name="Rose Quartz Facial Roller",
                description="Natural stone facial roller that helps reduce puffiness and improve circulation.",
                price=28.00,
                category="tools",
                image_url="https://images.unsplash.com/photo-1616394584738-fc6e612e71b9?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8ZmFjaWFsIHJvbGxlcnx8fHx8fDE2ODAxMjQyMzA&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all"],
                concerns=["puffiness", "circulation", "self-care"]
            ),
            Product(
                name="Ceramide Barrier Repair Cream",
                description="Strengthens skin barrier with essential ceramides and fatty acids.",
                price=42.99,
                category="moisturizer",
                image_url="https://images.unsplash.com/photo-1571781565036-d3f759be73e4?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8Y3JlYW18fHx8fHwxNjgwMTI0Mjgw&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["sensitive", "dry", "damaged"],
                concerns=["barrier repair", "sensitivity", "dryness"]
            ),
            Product(
                name="Detoxifying Charcoal Cleanser",
                description="Deep-cleansing face wash with activated charcoal to draw out impurities.",
                price=21.99,
                category="cleanser",
                image_url="https://images.unsplash.com/photo-1608248543803-ba4f8c70ae0b?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8Y2hhcmNvYWx8fHx8fHwxNjgwMTI0MzI5&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["oily", "combination", "acne-prone"],
                concerns=["acne", "oiliness", "congestion"]
            ),
            Product(
                name="Overnight Hydration Mask",
                description="Intensive hydrating sleep mask that works while you rest.",
                price=38.50,
                category="mask",
                image_url="https://images.unsplash.com/photo-1509099964906-67a15cf75cea?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8bWFza3x8fHx8fDE2ODAxMjQzODU&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["dry", "dehydrated", "normal"],
                concerns=["dryness", "dehydration", "dullness"]
            ),
            Product(
                name="Peptide Eye Cream",
                description="Reduces dark circles and fine lines with advanced peptide technology.",
                price=52.00,
                category="eye care",
                image_url="https://images.unsplash.com/photo-1562887284-8ba6b7c90fd8?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8ZXllIGNyZWFtfHx8fHx8MTY4MDEyNDQ0NQ&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["all", "mature"],
                concerns=["dark circles", "fine lines", "puffiness"]
            ),
            Product(
                name="AHA/BHA Exfoliating Solution",
                description="Chemical exfoliant with alpha and beta hydroxy acids for smoother skin.",
                price=36.99,
                category="exfoliant",
                image_url="https://images.unsplash.com/photo-1615397349754-cfa2066a298e?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8dG9uZXJ8fHx8fHwxNjgwMTI0NTAw&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["combination", "oily", "acne-prone"],
                concerns=["texture", "acne", "blackheads"]
            ),
            Product(
                name="Green Tea Mattifying Primer",
                description="Oil-controlling primer with antioxidant-rich green tea extract.",
                price=27.99,
                category="primer",
                image_url="https://images.unsplash.com/photo-1508810273804-4f1051a57102?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8Z3JlZW4gdGVhfHx8fHx8MTY4MDEyNDU0Mw&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["oily", "combination"],
                concerns=["oiliness", "pores", "makeup longevity"]
            ),
            Product(
                name="Calming CBD Facial Oil",
                description="Reduces inflammation and redness with hemp-derived CBD and essential oils.",
                price=49.99,
                category="oil",
                image_url="https://images.unsplash.com/photo-1617952385804-7e286ca3ee32?crop=entropy&cs=tinysrgb&fit=crop&fm=jpg&h=500&ixid=MnwxfDB8MXxyYW5kb218MHx8Y2JkIG9pbHx8fHx8fDE2ODAxMjQ2MDU&ixlib=rb-4.0.3&q=80&w=500",
                skin_type=["sensitive", "reactive", "acne-prone"],
                concerns=["redness", "irritation", "inflammation"]
            )
        ]
        db.session.add_all(sample_products)
        db.session.commit()
        logger.info("Sample products added to database")

# Configure upload settings
UPLOAD_FOLDER = 'static/images/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for product upload page
@app.route('/upload-product', methods=['GET', 'POST'])
@login_required
def upload_product():
    # User is already authenticated due to @login_required decorator
    # Create a form object for CSRF protection
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Get form data
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        category = request.form.get('category')
        skin_types = request.form.getlist('skin_type')
        concerns = request.form.getlist('concerns')
        
        # Validate required fields
        if not name or not description or not price or not category:
            flash('All fields are required', 'danger')
            return redirect(url_for('upload_product'))
        
        # Check if the post request has the file part
        if 'product_image' not in request.files:
            flash('No image file provided', 'danger')
            return redirect(url_for('upload_product'))
        
        file = request.files['product_image']
        
        # If user doesn't select a file, browser submits an empty file
        if file.filename == '':
            flash('No image file selected', 'danger')
            return redirect(url_for('upload_product'))
        
        # Save the file if it's allowed
        if file and allowed_file(file.filename):
            # Create a unique filename with timestamp and UUID
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}.{file_ext}"
            
            # Make sure the upload folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Create the image URL (relative to static folder)
            image_url = os.path.join('images/products', unique_filename)
            
            try:
                # Create new product
                from models import Product
                new_product = Product(
                    name=name,
                    description=description,
                    price=float(price),
                    category=category,
                    image_url=image_url,
                    skin_type=skin_types,
                    concerns=concerns
                )
                
                db.session.add(new_product)
                db.session.commit()
                
                flash('Product uploaded successfully!', 'success')
                return redirect(url_for('products'))
            
            except Exception as e:
                logger.error(f"Error creating product: {str(e)}")
                flash('An error occurred while saving the product', 'danger')
                return redirect(url_for('upload_product'))
        else:
            flash('Invalid file type. Please upload a JPG, PNG, JPEG, or GIF image', 'danger')
            return redirect(url_for('upload_product'))
    
    return render_template('upload_product.html', form=form)

# Admin access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in using Flask-Login
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Check if user is an admin
        if not current_user.is_admin:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    from models import Product, User
    from sqlalchemy import func
    
    # Get statistics for dashboard
    total_products = Product.query.count()
    total_users = User.query.count()
    total_stock = db.session.query(db.func.sum(Product.stock_quantity)).scalar() or 0
    low_stock = Product.query.filter(Product.stock_quantity <= 5, Product.stock_quantity > 0).count()
    out_of_stock = Product.query.filter(Product.stock_quantity == 0).count()
    
    # Get recent products and users
    recent_products = Product.query.order_by(Product.date_added.desc()).limit(5).all()
    recent_users = User.query.order_by(User.date_joined.desc()).limit(5).all()
    
    # Get more detailed user statistics
    users_with_skin_data = User.query.filter(User.skin_type.isnot(None)).count()
    newsletter_subscribers = User.query.filter_by(receive_newsletter=True).count()
    
    # Get recent users (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    new_users_30_days = User.query.filter(User.date_joined >= thirty_days_ago).count()
    
    # Get product category distribution
    category_counts = db.session.query(
        Product.category, 
        func.count(Product.id).label('count')
    ).group_by(Product.category).all()
    
    categories = [item[0] for item in category_counts]
    category_data = [item[1] for item in category_counts]
    
    # Get skin type distribution from users
    skin_type_counts = db.session.query(
        User.skin_type,
        func.count(User.id).label('count')
    ).filter(User.skin_type.isnot(None)).group_by(User.skin_type).all()
    
    skin_types = [item[0] for item in skin_type_counts]
    skin_type_data = [item[1] for item in skin_type_counts]
    
    stats = {
        'total_products': total_products,
        'total_users': total_users,
        'total_stock': total_stock,
        'low_stock': low_stock,
        'out_of_stock': out_of_stock,
        'users_with_skin_data': users_with_skin_data,
        'newsletter_subscribers': newsletter_subscribers,
        'new_users_30_days': new_users_30_days,
        'categories': categories,
        'category_data': category_data,
        'skin_types': skin_types,
        'skin_type_data': skin_type_data
    }
    
    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_products=recent_products,
        recent_users=recent_users,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/admin/products')
@admin_required
def admin_products():
    from models import Product
    
    # Get query parameters for filtering
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    stock_status = request.args.get('stock', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = Product.query
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                Product.sku.ilike(f'%{search}%')
            )
        )
    
    if category:
        query = query.filter(Product.category == category)
    
    if stock_status:
        if stock_status == 'in_stock':
            query = query.filter(Product.stock_quantity > 5)
        elif stock_status == 'low_stock':
            query = query.filter(Product.stock_quantity <= 5, Product.stock_quantity > 0)
        elif stock_status == 'out_of_stock':
            query = query.filter(Product.stock_quantity == 0)
    
    # Get total count for pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Get paginated products
    products = query.order_by(Product.name).paginate(page=page, per_page=per_page, error_out=False).items
    
    # Get all distinct categories for filter dropdown
    categories = db.session.query(Product.category).distinct().order_by(Product.category).all()
    categories = [c[0] for c in categories if c[0]]
    
    return render_template(
        'admin/products.html',
        products=products,
        categories=categories,
        page=page,
        total_pages=total_pages,
        total=total
    )

@app.route('/admin/inventory')
@admin_required
def admin_inventory():
    from models import Product
    
    # Get query parameters for filtering
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    stock_status = request.args.get('stock_status', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = Product.query
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                Product.sku.ilike(f'%{search}%')
            )
        )
    
    if category:
        query = query.filter(Product.category == category)
    
    if stock_status:
        if stock_status == 'in_stock':
            query = query.filter(Product.stock_quantity > 5)
        elif stock_status == 'low_stock':
            query = query.filter(Product.stock_quantity <= 5, Product.stock_quantity > 0)
        elif stock_status == 'out_of_stock':
            query = query.filter(Product.stock_quantity == 0)
    
    # Get total count for pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Get paginated products
    products = query.order_by(Product.name).paginate(page=page, per_page=per_page, error_out=False).items
    
    # Get all distinct categories for filter dropdown
    categories = db.session.query(Product.category).distinct().order_by(Product.category).all()
    categories = [c[0] for c in categories if c[0]]
    
    # Get inventory statistics
    in_stock = Product.query.filter(Product.stock_quantity > 5).count()
    low_stock = Product.query.filter(Product.stock_quantity <= 5, Product.stock_quantity > 0).count()
    out_of_stock = Product.query.filter(Product.stock_quantity == 0).count()
    total_stock = db.session.query(db.func.sum(Product.stock_quantity)).scalar() or 0
    
    stats = {
        'total_stock': total_stock,
        'in_stock': in_stock,
        'low_stock': low_stock,
        'out_of_stock': out_of_stock
    }
    
    return render_template(
        'admin/inventory.html',
        products=products,
        categories=categories,
        stats=stats,
        page=page,
        total_pages=total_pages,
        total=total
    )

@app.route('/admin/inventory/update-stock', methods=['POST'])
@admin_required
def update_product_stock():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        
        if not product_id or quantity is None:
            return jsonify({'success': False, 'message': 'Invalid request parameters'})
        
        # Convert quantity to integer
        try:
            quantity = int(quantity)
            if quantity < 0:
                return jsonify({'success': False, 'message': 'Quantity cannot be negative'})
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid quantity value'})
        
        # Update product stock
        from models import Product
        product = Product.query.get(product_id)
        
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        # Record previous quantity for history
        previous_quantity = product.stock_quantity
        
        # Update the stock quantity
        product.stock_quantity = quantity
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Stock updated successfully'})
    
    except Exception as e:
        logger.error(f"Error updating stock: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/inventory/bulk-update', methods=['POST'])
@admin_required
def bulk_update_inventory():
    try:
        data = request.get_json()
        action = data.get('action')
        quantity = data.get('quantity')
        product_ids = data.get('product_ids', [])
        
        if not action or not quantity or not product_ids:
            return jsonify({'success': False, 'message': 'Invalid request parameters'})
        
        # Convert quantity to integer
        try:
            quantity = int(quantity)
            if quantity < 0:
                return jsonify({'success': False, 'message': 'Quantity cannot be negative'})
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid quantity value'})
        
        # Update products based on action
        from models import Product
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        for product in products:
            if action == 'update':
                product.stock_quantity = quantity
            elif action == 'increment':
                product.stock_quantity = product.stock_quantity + quantity
            elif action == 'decrement':
                product.stock_quantity = max(0, product.stock_quantity - quantity)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Successfully updated stock for {len(products)} products'
        })
    
    except Exception as e:
        logger.error(f"Error bulk updating inventory: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users')
@admin_required
def admin_users():
    from models import User
    
    # Get query parameters for filtering
    search = request.args.get('search', '')
    role = request.args.get('role', '')
    newsletter = request.args.get('newsletter', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = User.query
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.first_name.ilike(f'%{search}%'),
                User.last_name.ilike(f'%{search}%')
            )
        )
    
    if role:
        if role == 'admin':
            query = query.filter(User.is_admin == True)
        elif role == 'user':
            query = query.filter(User.is_admin == False)
    
    if newsletter:
        if newsletter == 'subscribed':
            query = query.filter(User.receive_newsletter == True)
        elif newsletter == 'unsubscribed':
            query = query.filter(User.receive_newsletter == False)
    
    # Get total count for pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Get paginated users
    users = query.order_by(User.date_joined.desc()).paginate(page=page, per_page=per_page, error_out=False).items
    
    # Get user statistics
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    newsletter_subscribers = User.query.filter_by(receive_newsletter=True).count()
    users_with_skin_data = User.query.filter(User.skin_type.isnot(None)).count()
    
    # Get recent sign ups (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_signups = User.query.filter(User.date_joined >= thirty_days_ago).count()
    
    # Get skin type distribution
    skin_type_counts = db.session.query(
        User.skin_type,
        db.func.count(User.id).label('count')
    ).filter(User.skin_type.isnot(None)).group_by(User.skin_type).all()
    
    stats = {
        'total_users': total_users,
        'total_admins': total_admins,
        'newsletter_subscribers': newsletter_subscribers,
        'users_with_skin_data': users_with_skin_data,
        'recent_signups': recent_signups
    }
    
    return render_template(
        'admin/users.html',
        users=users,
        stats=stats,
        page=page,
        total_pages=total_pages,
        total=total,
        skin_type_counts=skin_type_counts
    )

@app.route('/admin/orders')
@admin_required
def admin_orders():
    # Sample order statistics data (placeholder)
    stats = {
        'total_orders': 134,
        'completed_orders': 98,
        'pending_orders': 36,
        'total_revenue': '9,854.00'
    }
    
    # Sample order data (placeholder for demonstration)
    sample_orders = [
        {
            'id': '10045',
            'customer': {'username': 'sarah_j'},
            'date': '2025-03-25',
            'status': 'completed',
            'items': 3,
            'total': '78.50'
        },
        {
            'id': '10044',
            'customer': {'username': 'mike_thomas'},
            'date': '2025-03-24',
            'status': 'shipped',
            'items': 2,
            'total': '125.00'
        },
        {
            'id': '10043',
            'customer': {'username': 'taylor_swift'},
            'date': '2025-03-23',
            'status': 'processing',
            'items': 5,
            'total': '210.75'
        },
        {
            'id': '10042',
            'customer': {'username': 'john_doe'},
            'date': '2025-03-22',
            'status': 'pending',
            'items': 1,
            'total': '45.99'
        },
        {
            'id': '10041',
            'customer': {'username': 'emma_garcia'},
            'date': '2025-03-21',
            'status': 'completed',
            'items': 4,
            'total': '156.25'
        },
        {
            'id': '10040',
            'customer': {'username': 'alex_wilson'},
            'date': '2025-03-20',
            'status': 'cancelled',
            'items': 2,
            'total': '65.00'
        }
    ]
    
    return render_template('admin/orders.html', stats=stats, sample_orders=sample_orders)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    # Serve the reports template with Chart.js visualizations
    # This is currently using static demo data
    return render_template('admin/reports.html')

@app.route('/admin/reviews')
@admin_required
def admin_reviews():
    from models import Review, Product, User
    from sqlalchemy import func
    
    # Get query parameters for filtering
    search = request.args.get('search', '')
    rating = request.args.get('rating', '')
    status = request.args.get('status', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query with joins
    query = db.session.query(Review).join(Product).join(User)
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%'),
                Review.title.ilike(f'%{search}%'),
                Review.comment.ilike(f'%{search}%')
            )
        )
    
    if rating:
        query = query.filter(Review.rating == int(rating))
    
    if status:
        if status == 'approved':
            query = query.filter(Review.is_approved == True)
        elif status == 'pending':
            query = query.filter(Review.is_approved == False)
    
    # Get total count for pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Get paginated reviews
    reviews = query.order_by(Review.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False).items
    
    # Get review statistics
    total_reviews = Review.query.count()
    
    # Calculate average rating
    avg_rating = db.session.query(func.avg(Review.rating)).scalar() or 0
    
    # Count pending reviews
    pending_reviews = Review.query.filter_by(is_approved=False).count()
    
    # Count recent reviews (last 7 days)
    seven_days_ago = datetime.now() - timedelta(days=7)
    recent_reviews = Review.query.filter(Review.created_at >= seven_days_ago).count()
    
    # Get rating distribution
    rating_counts = {}
    for i in range(1, 6):
        rating_counts[i] = Review.query.filter_by(rating=i).count()
    
    stats = {
        'total_reviews': total_reviews,
        'average_rating': avg_rating,
        'pending_reviews': pending_reviews,
        'recent_reviews': recent_reviews,
        'rating_counts': rating_counts
    }
    
    return render_template(
        'admin/reviews.html',
        reviews=reviews,
        stats=stats,
        page=page,
        total_pages=total_pages,
        total=total
    )

@app.route('/admin/reviews/<int:review_id>/details')
@admin_required
def review_details(review_id):
    from models import Review
    review = Review.query.get_or_404(review_id)
    
    review_data = {
        'id': review.id,
        'rating': review.rating,
        'title': review.title,
        'comment': review.comment,
        'created_at': review.created_at.isoformat(),
        'is_approved': review.is_approved,
        'product': {
            'id': review.product.id,
            'name': review.product.name,
            'image_url': review.product.image_url
        },
        'user': {
            'id': review.user.id,
            'username': review.user.username
        }
    }
    
    return jsonify({'success': True, 'review': review_data})

@app.route('/admin/reviews/<int:review_id>/approve', methods=['POST'])
@admin_required
def approve_review(review_id):
    from models import Review
    review = Review.query.get_or_404(review_id)
    
    review.is_approved = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Review approved successfully'})

@app.route('/admin/reviews/<int:review_id>/delete', methods=['POST'])
@admin_required
def delete_review(review_id):
    from models import Review
    review = Review.query.get_or_404(review_id)
    
    db.session.delete(review)
    db.session.commit()
    
    flash('Review deleted successfully', 'success')
    return redirect(url_for('admin_reviews'))

@app.route('/admin/reviews/batch-approve', methods=['POST'])
@admin_required
def batch_approve_reviews():
    data = request.get_json()
    review_ids = data.get('review_ids', [])
    
    if not review_ids:
        return jsonify({'success': False, 'message': 'No reviews selected'})
    
    from models import Review
    reviews = Review.query.filter(Review.id.in_(review_ids)).all()
    
    for review in reviews:
        review.is_approved = True
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Successfully approved {len(reviews)} reviews'})

@app.route('/admin/reviews/batch-delete', methods=['POST'])
@admin_required
def batch_delete_reviews():
    data = request.get_json()
    review_ids = data.get('review_ids', [])
    
    if not review_ids:
        return jsonify({'success': False, 'message': 'No reviews selected'})
    
    from models import Review
    reviews = Review.query.filter(Review.id.in_(review_ids)).all()
    
    for review in reviews:
        db.session.delete(review)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Successfully deleted {len(reviews)} reviews'})

# API endpoint for users to submit reviews
@app.route('/api/reviews/submit', methods=['POST'])
@login_required
def submit_review():
    # User is authenticated thanks to @login_required decorator
    
    data = request.get_json()
    product_id = data.get('product_id')
    rating = data.get('rating')
    title = data.get('title')
    comment = data.get('comment')
    
    # Validate required fields
    if not product_id or not rating:
        return jsonify({'success': False, 'message': 'Product ID and rating are required'}), 400
    
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid rating value'}), 400
    
    # Check if product exists
    from models import Product, Review
    product = Product.query.get(product_id)
    
    if not product:
        return jsonify({'success': False, 'message': 'Product not found'}), 404
    
    # Check if user already reviewed this product
    existing_review = Review.query.filter_by(
        product_id=product_id,
        user_id=current_user.id
    ).first()
    
    if existing_review:
        # Update existing review
        existing_review.rating = rating
        existing_review.title = title
        existing_review.comment = comment
        existing_review.updated_at = datetime.utcnow()
        existing_review.is_approved = False  # Require re-approval
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Review updated successfully and will be visible after approval',
            'review_id': existing_review.id
        })
    
    # Create new review
    new_review = Review(
        product_id=product_id,
        user_id=current_user.id,
        rating=rating,
        title=title,
        comment=comment,
        is_approved=False  # Require approval
    )
    
    db.session.add(new_review)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Review submitted successfully and will be visible after approval',
        'review_id': new_review.id
    })

@app.route('/admin/edit-product/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    from models import Product
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        # Update product details
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.category = request.form.get('category')
        product.stock_quantity = int(request.form.get('stock_quantity', 0))
        product.sku = request.form.get('sku')
        product.is_active = 'is_active' in request.form
        
        # Update skin types and concerns
        product.skin_type = request.form.getlist('skin_type')
        product.concerns = request.form.getlist('concerns')
        
        # Handle image upload if a new one is provided
        if 'product_image' in request.files and request.files['product_image'].filename:
            file = request.files['product_image']
            if allowed_file(file.filename):
                # Create a unique filename
                filename = secure_filename(file.filename)
                file_ext = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}.{file_ext}"
                
                # Make sure the upload folder exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                # Save the file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                # Update the product image URL
                product.image_url = os.path.join('images/products', unique_filename)
        
        # Save changes
        db.session.commit()
        
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    return render_template('admin/edit_product.html', product=product)

# Create a route to make a user an admin
@app.route('/admin/make-admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    from models import User
    user = User.query.get_or_404(user_id)
    
    user.is_admin = True
    db.session.commit()
    
    flash(f'User {user.username} is now an admin', 'success')
    return redirect(url_for('admin_users'))

# Blog routes
@app.route('/blog')
def blog():
    """Blog homepage with pagination and search"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 9
    
    from models import BlogPost
    query = BlogPost.query.filter_by(is_published=True)
    
    if search:
        query = query.filter(BlogPost.title.ilike(f'%{search}%') | BlogPost.content.ilike(f'%{search}%'))
        
    query = query.order_by(BlogPost.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    blog_posts = pagination.items
    total_pages = pagination.pages
    
    return render_template('blog/index.html', blog_posts=blog_posts, page=page, total_pages=total_pages)

@app.route('/blog/post/<slug>')
def view_blog_post(slug):
    """View a single blog post"""
    from models import BlogPost
    from flask_wtf import FlaskForm
    
    blog_post = BlogPost.query.filter_by(slug=slug, is_published=True).first_or_404()
    
    # Get related posts by category or author
    related_posts = BlogPost.query.filter(
        BlogPost.is_published == True,
        BlogPost.id != blog_post.id,
        (BlogPost.category == blog_post.category) | (BlogPost.user_id == blog_post.user_id)
    ).order_by(BlogPost.created_at.desc()).limit(3).all()
    
    # Create a minimal form for CSRF protection
    form = FlaskForm()
    
    return render_template('blog/view_post.html', blog_post=blog_post, related_posts=related_posts, form=form)

@app.route('/blog/create', methods=['GET', 'POST'])
@login_required
def create_blog_post():
    """Create a new blog post"""
    from forms import BlogPostForm
    form = BlogPostForm()
    
    if form.validate_on_submit():
        filename = None
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}.{image_file.filename.rsplit('.', 1)[1].lower()}")
                image_path = os.path.join(app.root_path, 'static/images/blog', filename)
                os.makedirs(os.path.dirname(image_path), exist_ok=True)
                image_file.save(image_path)
                filename = f"/static/images/blog/{filename}"
                
        from models import BlogPost
        blog_post = BlogPost(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id,
            category=form.category.data,
            image_url=filename,
            is_published=form.is_published.data
        )
        
        db.session.add(blog_post)
        db.session.commit()
        
        flash('Your blog post has been created!', 'success')
        return redirect(url_for('view_blog_post', slug=blog_post.slug))
    
    return render_template('blog/create_post.html', form=form)

@app.route('/blog/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_blog_post(post_id):
    """Edit a blog post"""
    from models import BlogPost
    from forms import BlogPostForm
    
    blog_post = BlogPost.query.get_or_404(post_id)
    
    # Check if the current user is the author or an admin
    if blog_post.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this post.', 'danger')
        return redirect(url_for('blog'))
    
    form = BlogPostForm()
    
    if request.method == 'GET':
        form.title.data = blog_post.title
        form.content.data = blog_post.content
        form.category.data = blog_post.category
        form.is_published.data = blog_post.is_published
    
    if form.validate_on_submit():
        blog_post.title = form.title.data
        blog_post.content = form.content.data
        blog_post.category = form.category.data
        blog_post.is_published = form.is_published.data
        
        # Handle image update
        if blog_post.image_url and not form.keep_image.data:
            # Remove old image if not keeping it
            old_image_path = os.path.join(app.root_path, blog_post.image_url.lstrip('/'))
            if os.path.exists(old_image_path):
                os.remove(old_image_path)
            blog_post.image_url = None
            
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                # Remove old image if it exists
                if blog_post.image_url:
                    old_image_path = os.path.join(app.root_path, blog_post.image_url.lstrip('/'))
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}.{image_file.filename.rsplit('.', 1)[1].lower()}")
                image_path = os.path.join(app.root_path, 'static/images/blog', filename)
                os.makedirs(os.path.dirname(image_path), exist_ok=True)
                image_file.save(image_path)
                blog_post.image_url = f"/static/images/blog/{filename}"
        
        db.session.commit()
        flash('Your blog post has been updated!', 'success')
        return redirect(url_for('view_blog_post', slug=blog_post.slug))
    
    return render_template('blog/edit_post.html', form=form, blog_post=blog_post)

@app.route('/blog/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_blog_post(post_id):
    """Delete a blog post"""
    from models import BlogPost
    
    blog_post = BlogPost.query.get_or_404(post_id)
    
    # Check if the current user is the author or an admin
    if blog_post.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('blog'))
    
    # Delete associated image if it exists
    if blog_post.image_url:
        image_path = os.path.join(app.root_path, blog_post.image_url.lstrip('/'))
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(blog_post)
    db.session.commit()
    
    flash('Your blog post has been deleted!', 'success')
    return redirect(url_for('blog'))

# User Profile Routes
@app.route('/profile')
@login_required
def profile():
    """Display user profile dashboard"""
    from models import Order, Review
    
    # Get recent orders
    recent_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.order_date.desc()).limit(5).all()
    
    # Get user reviews
    user_reviews = Review.query.filter_by(user_id=current_user.id, is_approved=True).order_by(Review.created_at.desc()).limit(4).all()
    
    return render_template('profile.html', active_tab='profile', recent_orders=recent_orders, user_reviews=user_reviews)

@app.route('/profile/orders')
@login_required
def order_history():
    """Display user's order history"""
    from models import Order
    
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.order_date.desc()).all()
    
    return render_template('profile.html', active_tab='orders', orders=orders)

@app.route('/profile/order/<int:order_id>')
@login_required
def view_order(order_id):
    """View details of a specific order"""
    from models import Order
    
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the current user
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this order.', 'danger')
        return redirect(url_for('order_history'))
    
    return render_template('order_detail.html', order=order)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user's profile information"""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        pincode = request.form.get('pincode')
        bio = request.form.get('bio')
        
        # Validate unique username and email
        from models import User
        
        if username != current_user.username and User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('profile'))
        
        if email != current_user.email and User.query.filter_by(email=email).first():
            flash('Email already in use.', 'danger')
            return redirect(url_for('profile'))
        
        # Update user data
        current_user.username = username
        current_user.email = email
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.phone = phone
        current_user.address = address
        current_user.city = city
        current_user.state = state
        current_user.pincode = pincode
        current_user.bio = bio
        
        # Handle profile picture upload
        if 'profile_pic' in request.files and request.files['profile_pic'].filename:
            file = request.files['profile_pic']
            if allowed_file(file.filename):
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}")
                image_path = os.path.join(app.root_path, 'static/images/users', filename)
                os.makedirs(os.path.dirname(image_path), exist_ok=True)
                file.save(image_path)
                
                # If user already has a profile pic, delete the old one
                if current_user.profile_pic:
                    old_path = os.path.join(app.root_path, current_user.profile_pic.lstrip('/'))
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                current_user.profile_pic = f"/static/images/users/{filename}"
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        
        return redirect(url_for('profile'))

@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    """Change user's password"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    # Check current password
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Your password has been updated!', 'success')
    return redirect(url_for('profile', _anchor='settings'))

@app.route('/profile/email-preferences', methods=['POST'])
@login_required
def update_email_preferences():
    """Update user's email preferences"""
    newsletter = 'newsletter' in request.form
    
    current_user.receive_newsletter = newsletter
    db.session.commit()
    
    flash('Your email preferences have been updated!', 'success')
    return redirect(url_for('profile', _anchor='settings'))

@app.route('/profile/skin')
@login_required
def skin_profile():
    """Display user's skin profile"""
    return render_template('profile.html', active_tab='skin')

@app.route('/profile/settings')
@login_required
def account_settings():
    """Display user's account settings"""
    return render_template('profile.html', active_tab='settings')

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    """Delete user's account"""
    password_confirm = request.form.get('password_confirm')
    confirm_deletion = 'confirm_deletion' in request.form
    
    if not password_confirm or not confirm_deletion:
        flash('All fields are required.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    # Verify password
    if not current_user.check_password(password_confirm):
        flash('Password is incorrect.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))
    
    try:
        # Remove any profile pic
        if current_user.profile_pic:
            image_path = os.path.join(app.root_path, current_user.profile_pic.lstrip('/'))
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Delete user account
        user_id = current_user.id
        logout_user()  # Log out the user first
        
        from models import User
        user = User.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
        
        flash('Your account has been deleted.', 'info')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting account: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('profile', _anchor='settings'))

# Call initialize_database within the app context
with app.app_context():
    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()
    initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
