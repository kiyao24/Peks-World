from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, DecimalField, SelectField, EmailField
from wtforms.validators import InputRequired, Length, Email, DataRequired, EqualTo
import phonenumbers
from flask_wtf.file import FileField, FileAllowed, FileRequired
from datetime import datetime



db = SQLAlchemy()


# ===================== Admin Login Model =====================

class AdminLogin(UserMixin, db.Model):
    __tablename__ = 'admin_logins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='staff')
    
    
    def __init__(self, username, password, role="staff"):
        self.username = username
        self.role = role
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_superadmin(self):
        return self.role == 'superadmin'

# ===================== User Model =====================

class Users(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    address = db.Column(db.String(100))
    phone = db.Column(db.String(15), nullable=False, unique=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(200), default='uploads/default-avatar.png')
    
    is_admin = db.Column(db.Boolean, default=True)

    def __init__(self, first_name, last_name, email, phone, address, username, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.address = address
        self.username = username
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ===================== Flask-WTF Forms =====================

class RegistrationForm(FlaskForm):
    First_name = StringField('First Name', validators=[InputRequired()])
    Last_name = StringField('Last Name', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    address = StringField('Address')
    phone = StringField('Phone', validators=[InputRequired()])
    submit = SubmitField('Register')
    def validate_phone(self, field):
        try:
            parsed = phonenumbers.parse(field.data, "NG")  # "NG" for Nigeria
            if not phonenumbers.is_valid_number(parsed):
                raise ValidationError("Invalid phone number format.")
        except phonenumbers.NumberParseException:
            raise ValidationError("Invalid phone number.")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# ===================== Category Model =====================

class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    products = db.relationship('Product', backref='category', lazy=True)

    def __init__(self, name):
        self.name = name

# ===================== Product Model =====================

class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)

    def __init__(self, name, price, category_id, description,image=None):
        self.name = name
        self.price = price
        self.category_id = category_id
        self.image = image
        self.description = description

# ===================== User-Category-Product Relationship =====================

class UserCategoryProduct(db.Model):
    __tablename__ = 'user_category_products'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    
class CategoryForm(FlaskForm):
    name = StringField("Category Name", validators=[InputRequired()]) 
    submit = SubmitField("Add Category")
    
    
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[InputRequired()])
    price = DecimalField('Price', validators=[InputRequired()])
    image = FileField('Product Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp', 'avif'], 'Images only!')
    ])
    category_id = SelectField('Category', coerce=int, validators=[InputRequired()])
    description = StringField('description')
    submit = SubmitField('Update Product')
    
    
    
class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    total_amount = db.Column(db.Float)  # Optional: store final amount
    discount = db.Column(db.Float, default=0.0)
    tax = db.Column(db.Float, default=0.0)
    shipping_fee = db.Column(db.Float, default=0.0)

    items = db.relationship('OrderItem', backref='order', lazy=True)

    @property
    def subtotal(self):
        return sum(item.price * item.quantity for item in self.items)

    @property
    def total(self):
        return self.subtotal - self.discount + self.tax + self.shipping_fee


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    product = db.relationship('Product', backref='order_items')



class EditProfileForm(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone")
    address = StringField("Address")
    submit = SubmitField("Update Profile")
 
    
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')
    
    
class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')
    
    
class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)