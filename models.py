from app import db
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import String, cast
import json
from datetime import datetime
from flask_login import UserMixin
import uuid

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    price = db.Column(db.Float, nullable=False)  # Price in INR
    category = db.Column(db.String(50))
    image_url = db.Column(db.String(500))  # Main product image
    # Store skin type and concerns as JSON strings
    _skin_type = db.Column("skin_type", db.String(200))
    _concerns = db.Column("concerns", db.String(200))
    
    # Stock and inventory information
    stock_quantity = db.Column(db.Integer, default=0)
    sku = db.Column(db.String(50), unique=True)
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_updated = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    is_active = db.Column(db.Boolean, default=True)
    
    # Additional product information
    brand = db.Column(db.String(100))
    ingredients = db.Column(db.Text)
    how_to_use = db.Column(db.Text)
    benefits = db.Column(db.Text)
    
    @property
    def skin_type(self):
        return json.loads(self._skin_type) if self._skin_type else []
    
    @skin_type.setter
    def skin_type(self, value):
        self._skin_type = json.dumps(value)
    
    @property
    def concerns(self):
        return json.loads(self._concerns) if self._concerns else []
    
    @concerns.setter
    def concerns(self, value):
        self._concerns = json.dumps(value)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,  # Price in INR
            'category': self.category,
            'image_url': self.image_url,
            'skin_type': self.skin_type,
            'concerns': self.concerns,
            'stock_quantity': self.stock_quantity,
            'sku': self.sku,
            'date_added': self.date_added.isoformat() if self.date_added else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'is_active': self.is_active,
            'brand': self.brand,
            'ingredients': self.ingredients,
            'how_to_use': self.how_to_use,
            'benefits': self.benefits,
            'additional_images': [img.to_dict() for img in self.additional_images] if hasattr(self, 'additional_images') else [],
            'reviews': [review.to_dict() for review in self.reviews] if hasattr(self, 'reviews') else []
        }

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    date_joined = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # User role (customer or admin)
    is_admin = db.Column(db.Boolean, default=False)
    
    # User's profile information
    profile_pic = db.Column(db.String(500))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(500))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    pincode = db.Column(db.String(20))
    bio = db.Column(db.Text)
    
    # User's skin profile based on selfie analysis
    skin_type = db.Column(db.String(50))
    skin_tone = db.Column(db.String(50))
    concerns = db.Column(db.String(200))  # Stored as JSON string
    
    # User preferences
    receive_newsletter = db.Column(db.Boolean, default=True)
    preferred_categories = db.Column(db.String(200))  # Stored as JSON string
    
    # Account settings
    email_verified = db.Column(db.Boolean, default=False)
    account_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    
    # Security methods
    def set_password(self, password):
        """Hash the password and store it in the database"""
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if the password is correct"""
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)
    
    # JSON serialization for concerns and preferences
    def set_concerns(self, concerns_list):
        self.concerns = json.dumps(concerns_list)
        
    def get_concerns(self):
        return json.loads(self.concerns) if self.concerns else []
        
    def set_preferred_categories(self, categories_list):
        self.preferred_categories = json.dumps(categories_list)
        
    def get_preferred_categories(self):
        return json.loads(self.preferred_categories) if self.preferred_categories else []
        
    def to_dict(self):
        """Convert user to dictionary for API"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'profile_pic': self.profile_pic,
            'phone': self.phone,
            'address': self.address,
            'city': self.city,
            'state': self.state,
            'pincode': self.pincode,
            'bio': self.bio,
            'date_joined': self.date_joined.isoformat() if self.date_joined else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'skin_type': self.skin_type,
            'skin_tone': self.skin_tone,
            'concerns': self.get_concerns(),
            'preferred_categories': self.get_preferred_categories(),
            'email_verified': self.email_verified,
            'account_active': self.account_active,
            'is_admin': self.is_admin
        }
        
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 star rating
    title = db.Column(db.String(100))
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=True)
    
    # Relationships
    product = db.relationship('Product', backref=db.backref('reviews', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'user_id': self.user_id,
            'username': self.user.username,
            'rating': self.rating,
            'title': self.title,
            'comment': self.comment,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_approved': self.is_approved
        }

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    image_url = db.Column(db.String(500))
    slug = db.Column(db.String(200), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_published = db.Column(db.Boolean, default=True)
    category = db.Column(db.String(50))
    
    # Relationships
    user = db.relationship('User', backref=db.backref('blog_posts', lazy=True))
    
    def __init__(self, *args, **kwargs):
        super(BlogPost, self).__init__(*args, **kwargs)
        if not self.slug:
            self.slug = f"{str(uuid.uuid4())[:8]}-{datetime.utcnow().strftime('%Y%m%d')}"
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'user_id': self.user_id,
            'username': self.user.username,
            'author_name': f"{self.user.first_name} {self.user.last_name}" if self.user.first_name else self.user.username,
            'image_url': self.image_url,
            'slug': self.slug,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_published': self.is_published,
            'category': self.category
        }

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, processing, shipped, delivered, cancelled
    total_amount = db.Column(db.Float, default=0.0)
    shipping_address = db.Column(db.String(500))
    contact_phone = db.Column(db.String(20))
    tracking_number = db.Column(db.String(50))
    
    # Relationships
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'order_date': self.order_date.isoformat() if self.order_date else None,
            'status': self.status,
            'total_amount': self.total_amount,
            'shipping_address': self.shipping_address,
            'contact_phone': self.contact_phone,
            'tracking_number': self.tracking_number,
            'order_items': [item.to_dict() for item in self.order_items]
        }

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='SET NULL'), nullable=True)
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Float, nullable=False)  # Price at time of order (may differ from current product price)
    
    # Relationships
    order = db.relationship('Order', backref=db.backref('order_items', lazy=True, cascade='all, delete-orphan'))
    product = db.relationship('Product')
    
    def to_dict(self):
        return {
            'id': self.id,
            'order_id': self.order_id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else 'Product no longer available',
            'quantity': self.quantity,
            'price': self.price,
            'subtotal': self.quantity * self.price
        }

class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    image_url = db.Column(db.String(500), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    display_order = db.Column(db.Integer, default=0)
    
    # Relationship
    product = db.relationship('Product', backref=db.backref('additional_images', lazy=True, cascade='all, delete-orphan'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'image_url': self.image_url,
            'is_primary': self.is_primary,
            'display_order': self.display_order
        }
