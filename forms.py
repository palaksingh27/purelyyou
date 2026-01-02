from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SelectField, BooleanField, FloatField, IntegerField, MultipleFileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, NumberRange, ValidationError
import email_validator

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[Optional(), Length(max=50)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=50)])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), 
        EqualTo('password', message='Passwords must match')
    ])
    
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('password', message='Passwords must match')
    ])

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    price = FloatField('Price (INR)', validators=[DataRequired(), NumberRange(min=0)])
    category = SelectField('Category', validators=[DataRequired()], choices=[
        ('cleanser', 'Cleanser'),
        ('moisturizer', 'Moisturizer'),
        ('serum', 'Serum'),
        ('toner', 'Toner'),
        ('exfoliant', 'Exfoliant'),
        ('mask', 'Mask'),
        ('suncare', 'Suncare'),
        ('eye_care', 'Eye Care'),
        ('treatment', 'Treatment'),
        ('lip_care', 'Lip Care')
    ])
    image = FileField('Product Image', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    additional_images = MultipleFileField('Additional Images', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    skin_type = SelectField('Suitable Skin Types', validators=[Optional()], choices=[
        ('all', 'All Skin Types'),
        ('dry', 'Dry'),
        ('oily', 'Oily'),
        ('combination', 'Combination'),
        ('sensitive', 'Sensitive'),
        ('normal', 'Normal')
    ])
    stock_quantity = IntegerField('Stock Quantity', validators=[DataRequired(), NumberRange(min=0)])
    sku = StringField('SKU', validators=[DataRequired(), Length(max=50)])
    brand = StringField('Brand', validators=[DataRequired(), Length(max=100)])
    ingredients = TextAreaField('Ingredients', validators=[Optional()])
    how_to_use = TextAreaField('How To Use', validators=[Optional()])
    benefits = TextAreaField('Benefits', validators=[Optional()])

class BlogPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=5, max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = SelectField('Category', validators=[DataRequired()], choices=[
        ('skincare', 'Skincare'),
        ('makeup', 'Makeup'),
        ('wellness', 'Wellness'),
        ('tips', 'Beauty Tips'),
        ('product_reviews', 'Product Reviews'),
        ('tutorials', 'Tutorials'),
        ('trends', 'Beauty Trends'),
        ('other', 'Other')
    ])
    image = FileField('Featured Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    is_published = BooleanField('Publish', default=True)
    keep_image = BooleanField('Keep current image', default=True)

class UserProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[Optional(), Length(max=50)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=50)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    address = TextAreaField('Address', validators=[Optional(), Length(max=500)])
    city = StringField('City', validators=[Optional(), Length(max=100)])
    state = StringField('State', validators=[Optional(), Length(max=100)])
    pincode = StringField('PIN Code', validators=[Optional(), Length(max=20)])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=500)])
    profile_pic = FileField('Profile Picture', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')
    ])
    receive_newsletter = BooleanField('Receive Newsletter', default=True)

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('new_password', message='Passwords must match')
    ])

class ReviewForm(FlaskForm):
    rating = SelectField('Rating', validators=[DataRequired()], choices=[
        ('5', '★★★★★ Excellent'),
        ('4', '★★★★☆ Good'),
        ('3', '★★★☆☆ Average'),
        ('2', '★★☆☆☆ Poor'),
        ('1', '★☆☆☆☆ Bad')
    ], coerce=int)
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    comment = TextAreaField('Review', validators=[DataRequired()])