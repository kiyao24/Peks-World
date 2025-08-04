from flask import Flask, render_template, session, redirect, request, url_for, flash,current_app, jsonify, abort
from app import *
from model import *
from werkzeug.utils import secure_filename
import os
from PIL import Image
import uuid
import requests
import functools
from functools import wraps


user = Blueprint('user', __name__, template_folder='templates')
admin = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin.admin_login'))
        return view(**kwargs)
    return wrapped_view

def is_superadmin(self):
    return self.role == 'superadmin'


def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_id = session.get('admin')
        if not admin_id:
            flash("You must be logged in as an admin.", "danger")
            return redirect(url_for('admin.admin_login'))

        current_admin = AdminLogin.query.get(admin_id)
        if 'admin' not in session or session.get('role') != 'superadmin':
            flash("Unauthorized: Super admin access required.", "danger")
            return redirect(url_for('admin.Admin_dashboard'))

        return f(*args, **kwargs)
    return decorated_function


@admin.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = AdminLogin.query.filter_by(username=username).first()
               
        if admin and admin.check_password(password):
            session['admin'] = True  # ✅ Save admin login state
            session['role'] = admin.role
            flash("Admin login successful.", "success")
            return redirect(url_for('admin.Admin_dashboard'))
        
        flash("Invalid login credentials.", "danger")
    return render_template('admin_login.html')


@admin.route('/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('admin.admin_register'))

        # Check if username already exists
        existing_admin = AdminLogin.query.filter_by(username=username).first()
        new_admin = AdminLogin(username=username, password=password)

        if existing_admin:
            flash("Username already taken.", "warning")
            return redirect(url_for('admin.admin_register'))

        # Create and save new admin
        new_admin.set_password(password)
        new_admin = AdminLogin(username=username, password=password)
        db.session.add(new_admin)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for('admin.admin_login'))

    return render_template('admin_register.html')



@admin.route('/add-admin', methods=['GET', 'POST'])
@superadmin_required
def add_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'staff')  # Default to 'staff'
        new_admin = AdminLogin(username=username, password=password,role=role)
        print(new_admin.role)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('admin.add_admin'))

        if AdminLogin.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return redirect(url_for('admin.add_admin'))

        if role not in ['staff', 'superadmin']:
            flash("Invalid role selected.", "danger")
            return redirect(url_for('admin.add_admin'))

        new_admin = AdminLogin(username=username, password=password,role=role)
        print(new_admin.role)
        db.session.add(new_admin)
        db.session.commit()

        flash(f"Admin '{username}' created successfully with role: {role}.", "success")
        return redirect(url_for('admin.admin_login'))

    return render_template('add_admin.html')



@admin.route('/admin-users')
@superadmin_required
def list_admins():
    admins = AdminLogin.query.all()
    return render_template('admin_list.html', admins=admins)



@admin.route('/update-admin-role/<int:admin_id>', methods=['POST'])
@superadmin_required
def update_admin_role(admin_id):
    admin_user = AdminLogin.query.get_or_404(admin_id)
    new_role = request.form.get('role')

    if new_role not in ['staff', 'superadmin']:
        flash("Invalid role selected.", "danger")
        return redirect(url_for('admin.list_admins'))

    # Prevent self-demotion
    if admin_user.id == current_user.id and new_role != 'superadmin':
        flash("You cannot change your own role.", "warning")
        return redirect(url_for('admin.list_admins'))

    admin_user.role = new_role
    db.session.commit()
    flash(f"Role updated to '{new_role}' for {admin_user.username}.", "success")
    return redirect(url_for('admin.list_admins'))


@admin.route('/delete-admin/<int:admin_id>', methods=['POST'])
@superadmin_required
def delete_admin(admin_id):
    admin_user = AdminLogin.query.get_or_404(admin_id)

    if admin_user.role == 'superadmin':
        flash("❌ You cannot delete another superadmin.", "danger")
        return redirect(url_for('admin.list_admins'))

    db.session.delete(admin_user)
    db.session.commit()
    flash("✅ Admin deleted successfully.", "success")
    return redirect(url_for('admin.list_admins'))





# View all users
@admin.route('/users')
@admin_required
def view_users():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    users = Users.query.all()
    return render_template('view_users.html', users=users)

# Delete a user
@admin.route('/delete-user/<int:id>')
@admin_required
def delete_user(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    user = Users.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.")
    return redirect(url_for('admin.view_users'))


@admin.route('/add-user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    if request.method == 'POST':
        username = request.form['username']
        phone = request.form['phone']
        email = request.form['email']

        if Users.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('admin.add_user'))

        if Users.query.filter_by(phone=phone).first():
            flash("Phone number already exists.", "danger")
            return redirect(url_for('admin.add_user'))

        if Users.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for('admin.add_user'))
        
        new_user = Users(
            first_name=request.form['first_name'],
            last_name=request.form['last_name'],
            username=request.form['username'],
            email=request.form['email'],
            phone=request.form['phone'],
            address=request.form['address'],
            password=request.form['password']
        )
        db.session.add(new_user)
        db.session.commit()
        flash("User added successfully.", "success")
        return redirect(url_for('admin.view_users'))
    return render_template('add_users.html')


@admin.route('/update-user/<int:id>', methods=['GET', 'POST'])
@admin_required
def update_user(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    user = Users.query.get_or_404(id)
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']
        user.phone = request.form['phone']
        user.address = request.form['address']
        user.username = request.form['username']
        if request.form['password']:
            user.set_password(request.form['password'])
        # Example: prevent duplicate username (for others, add similar checks)
        existing_user = Users.query.filter(Users.username == request.form['username'], Users.id != id).first()
        if existing_user:
            flash("Username already taken.", "danger")
            return redirect(request.url)
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin.Admin_dashboard'))
    return render_template('user_update.html', user=user)




# View & delete categories
@admin.route('/categories')
@admin_required
def list_categories():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    categories = Category.query.all()
    return render_template('view_categories.html', categories=categories)


@admin.route('/delete-category/<int:id>')
@admin_required
def delete_category(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    category = Category.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    flash("Category deleted.", "info")
    return redirect(url_for('admin.list_categories'))


@admin.route('/update-category/<int:id>', methods=['GET', 'POST'])
@admin_required
def update_category(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    category = Category.query.get_or_404(id)
    form = CategoryForm(obj=category)
    if form.validate_on_submit():
        category.name = request.form['name']
        db.session.commit()
        flash("Category updated.", "success")
        return redirect(url_for('admin.Admin_dashboard'))
    return render_template('update_category.html', form=form)


# Add Category
@admin.route('/add-category', methods=['GET', 'POST'])
@admin_required
def add_category():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    form = CategoryForm()
    if form.validate_on_submit():
        name = form.name.data
        existing = Category.query.filter_by(name=name).first()
        if existing:
            flash("Category already exists.", "warning")
            return redirect(url_for('admin.add_category'))
        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()
        flash("Category added.")
        return redirect(url_for('admin.add_category'))
    return render_template('add_category.html', form=form)



@admin.route('/add-product', methods=['GET', 'POST'])
@admin_required
def add_product():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    form = ProductForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        image_file = form.image.data
        filename = secure_filename(image_file.filename)
        upload_path = os.path.join(current_app.root_path, 'static/uploads', filename)
        image_file.save(upload_path)
        
        new_product = Product(
            name=request.form['name'],
            price=float(request.form['price']),
            image=f'uploads/{filename}',
            category_id=form.category_id.data,
            description = request.form['description']
        )
        db.session.add(new_product)
        db.session.commit()
        flash("Product added.", "success")
        return redirect(url_for('admin.list_products'))
    return render_template('add_product.html', form=form)


@admin.route('/products')
@admin_required
def list_products():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    products = Product.query.all()
    return render_template('view_products.html', products=products)


@admin.route('/product/<int:id>')
@admin_required
def select_product(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    product = Product.query.get_or_404(id)
    return render_template('view_product.html', product=product)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("product_detail.html", product=product)



@admin.route('/delete-product/<int:id>')
@admin_required
def delete_product(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash("Product deleted.", "info")
    return redirect(url_for('admin.list_products'))



ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
MAX_IMAGE_SIZE_MB = 2

def is_allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_too_large(file_obj):
    file_obj.seek(0, os.SEEK_END)
    size_mb = file_obj.tell() / (1024 * 1024)
    file_obj.seek(0)  # Reset file pointer
    return size_mb > MAX_IMAGE_SIZE_MB


@admin.route('/update-product/<int:id>', methods=['GET', 'POST'])
@admin_required
def update_product(id):
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    product = Product.query.get_or_404(id)
    form = ProductForm(obj=product)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.category_id = form.category_id.data
        product.description = form.description.data

        # Check if a new image is uploaded
        if form.image.data:
            image_file = form.image.data
            filename = secure_filename(image_file.filename)

            if not is_allowed_image(filename):
                flash("Invalid image format. Allowed: jpg, jpeg, png, gif, webp", "danger")
                return redirect(request.url)

            if is_image_too_large(image_file):
                flash("Image file too large. Maximum allowed is 2MB.", "danger")
                return redirect(request.url)

            # Delete old image if it exists
            if product.image:
                old_image_path = os.path.join(current_app.root_path, 'static', product.image)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

            # Save new image
            upload_dir = os.path.join(current_app.root_path, 'static/uploads')
            os.makedirs(upload_dir, exist_ok=True)
            image_path = os.path.join(upload_dir, filename)
            image_file.save(image_path)

            # Save relative path to database
            product.image = f'uploads/{filename}'

        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('admin.list_products'))

    return render_template('update_product.html', form=form, product=product)



@admin.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('admin.admin_login'))

# Admin Dashboard
@admin.route('/admin/dashboard')
@admin_required
def Admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin.admin_login'))
    users = Users.query.all()
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('admin_dashboard.html', users=users, categories=categories, products=products)



@user.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_admin:
    #     return render_template('admin_dashboard.html', user=current_user)
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('defaulthomepage'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)


@user.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = Users(
        first_name = form.First_name.data,
        last_name = form.Last_name.data,
        address = form.address.data,
        phone = form.phone.data,
        username=form.username.data,
        email=form.email.data,
        password= form.password.data
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('user.login'))
    return render_template('register.html', form=form)



@user.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = EditProfileForm(obj=current_user)

    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        current_user.phone = form.phone.data
        current_user.address = form.address.data
        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('user.dashboard'))

    # if current_user.is_admin:
    #     return render_template('admin_dashboard.html', user=current_user)

    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('user_dashboard.html', user=current_user, form=form,
    password_form=ChangePasswordForm(), orders=orders)



@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully.', 'success')
        else:
            flash('Current password incorrect.', 'danger')
    return redirect(url_for('user.dashboard'))


@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        current_user.phone = form.phone.data
        current_user.address = form.address.data
        
        if form.avatar.data:
            avatar_file = form.avatar.data
            ext = avatar_file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{ext}"
            avatar_path = os.path.join(app.static_folder, 'uploads', unique_filename)
            
            image = Image.open(avatar_file)
            image = image.convert('RGB')  # ensure consistent format
            image.thumbnail((300, 300))  # Resize to max 300x300
            image.save(avatar_path, optimize=True)

            # Delete old avatar if not default
            old_avatar = current_user.avatar
            if old_avatar != 'default-avatar.png':
                old_path = os.path.join(app.static_folder, old_avatar)
                if os.path.exists(old_path):
                    os.remove(old_path)
                    
            current_user.avatar = f'uploads/{unique_filename}'
        db.session.commit()
        flash("Profile updated successfully.", "success")
    else:
        flash("Failed to update profile.", "danger")
        return redirect(url_for('user.dashboard'))


@app.route('/upload-profile-image', methods=['POST'])
@login_required
def upload_profile_image():
    file = request.files.get('profile_image')
    if file:
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Resize with Pillow
        image = Image.open(file)
        image = image.resize((200, 200))
        image.save(path)

        current_user.profile_image = filename
        db.session.commit()
        flash('Profile image updated!', 'success')
    return redirect(url_for('dashboard'))



@user.route('/delete-avatar')
@login_required
def delete_avatar():
    # Delete old avatar if not default
    if current_user.avatar != 'uploads/default-avatar.png':
        path = os.path.join(app.static_folder, current_user.avatar)
        if os.path.exists(path):
            os.remove(path)
        current_user.avatar = 'uploads/default-avatar.png'
        db.session.commit()
        flash('Avatar removed successfully', 'info')
    else:
        flash('No custom avatar to delete.', 'warning')

    return redirect(url_for('dashboard'))


@user_settings.route('/')
@login_required
def settings_dashboard():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template("user_settings.html", notifications=notifications)

@user_settings.route('/mark-read/<int:notification_id>')
@login_required
def mark_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    notification.read = True
    db.session.commit()
    flash("Notification marked as read.", "info")
    return redirect(url_for('settings.settings_dashboard'))

@user_settings.route('/delete/<int:notification_id>')
@login_required
def delete_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    db.session.delete(notification)
    db.session.commit()
    flash("Notification deleted.", "info")
    return redirect(url_for('settings.settings_dashboard'))



@user.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('user.login'))



@app.route('/')
def defaulthomepage():  
    page = request.args.get('page', 1, type=int)
    per_page = 15
    category_id = request.args.get('category', type=int)
    search = request.args.get('q', '')

    categories = Category.query.all()
    selected_category = None

    # Base query
    query = Product.query

    if search:
        query = query.filter(Product.name.ilike(f"%{search}%"))

    if category_id:
        query = query.filter_by(category_id=category_id)
        selected_category = Category.query.get(category_id)

    products_paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        'homepage.html',
        products=products_paginated.items,
        pages=products_paginated,
        categories=categories,
        selected_category=selected_category,
        search=search
    )
    

@app.context_processor
def inject_cart_count():
    cart = session.get('cart', {})
    return dict(cart_count=sum(cart.values()))



@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return dict(cart_count=sum(session.get('cart', {}).values()), unread_notifications=unread_count)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    cart = session.get('cart', {})  # e.g. { "1": 2, "5": 1 }
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session['cart'] = cart

    cart_count = sum(cart.values())

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'message': f"{product.name} added to cart!",
            'cart_count': cart_count
        })

    flash(f"{product.name} added to cart!", 'success')
    return redirect(request.referrer or url_for('defaulthomepage'))



@app.route('/cart')
def view_cart():
    cart = session.get('cart', {})  # same structure: { "1": 2, "5": 1 }
    cart_items = []
    total = 0

    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            subtotal = product.price * quantity
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'subtotal': subtotal
            })
            total += subtotal

    return render_template('cart.html', cart_items=cart_items, total=total)





@app.route('/remove/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    if str(product_id) in cart:
        del cart[str(product_id)]
    session['cart'] = cart
    return redirect(url_for('view_cart'))



@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    cart = session.get('cart', {})

    # Assume multiple product_id[] and quantity[] inputs
    product_ids = request.form.getlist('product_id')
    quantities = request.form.getlist('quantity')

    for pid, qty in zip(product_ids, quantities):
        try:
            qty = int(qty)
            if qty > 0:
                cart[pid] = qty
            else:
                cart.pop(pid, None)
        except ValueError:
            continue  # Skip any non-integer input

    session['cart'] = cart
    flash('Cart updated successfully.', 'success')
    return redirect(url_for('view_cart'))




@app.route('/clear-cart')
def clear_cart():
    session.pop('cart', None)
    flash("Cart cleared.")
    return redirect(url_for('view_cart'))



def calculate_order_summary(cart):
    cart_items = []
    subtotal = 0

    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))
        if product:
            subtotal_item = product.price * quantity
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'subtotal': subtotal_item
            })
            subtotal += subtotal_item

    discount = subtotal * 0.05 if subtotal >= 10000 else 0
    tax = (subtotal - discount) * 0.075
    shipping_fee = 1500 if subtotal < 20000 else 0
    total = (subtotal - discount) + tax + shipping_fee

    order_summary = {
        'cart_items': cart_items,
        'subtotal': subtotal,
        'discount': discount,
        'tax': tax,
        'shipping_fee': shipping_fee,
        'total': total
    }

    return order_summary



@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty.")
        return redirect(url_for('defaulthomepage'))

    summary = calculate_order_summary(cart)

    if request.method == 'POST':
        new_order = Order(user_id=current_user.id, total_amount=summary['total'])
        db.session.add(new_order)
        db.session.flush()

        for item in summary['cart_items']:
            db.session.add(OrderItem(
                order=new_order,
                product_id=item['product'].id,
                quantity=item['quantity'],
                price=item['product'].price
            ))

        db.session.commit()
        session.pop('cart', None)
        flash("✅ Order placed successfully.")
        return redirect(url_for('defaulthomepage'))

    return render_template('checkout.html', cart_items=summary['cart_items'], order=summary, total=summary['total'])





@app.route('/api/checkout', methods=['POST'])
@login_required
def api_checkout():
    data = request.get_json()
    cart = data.get('cart', {})
    if not cart:
        return jsonify({'error': 'Cart is empty'}), 400

    try:
        summary = calculate_order_summary(cart)

        new_order = Order(
            user_id=current_user.id,
            total_amount=summary['total'],
            discount=summary['discount'],
            tax=summary['tax'],
            shipping_fee=summary['shipping_fee']
        )
        db.session.add(new_order)
        db.session.flush()

        for item in summary['cart_items']:
            db.session.add(OrderItem(
                order=new_order,
                product_id=item['product'].id,
                quantity=item['quantity'],
                price=item['product'].price
            ))

        db.session.commit()

        # Redirect to payment page
        return jsonify({'redirect_url': url_for('payment_page', order_id=new_order.id)}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    


@app.route('/payment/<int:order_id>')
@login_required
def payment_page(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return render_template('payment_page.html', order=order)



@app.route('/pay/paystack/<int:order_id>')
@login_required
def paystack_pay(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}",
        "Content-Type": "application/json"
    }
    data = {
        "email": current_user.email,
        "amount": int(order.total_amount * 100),  # Convert to kobo
        "callback_url": url_for('payment_success', order_id=order.id, _external=True),
        "metadata": {
            "order_id": order.id
        }
    }

    response = requests.post(url, json=data, headers=headers)
    result = response.json()

    if result.get('status'):
        return redirect(result['data']['authorization_url'])
    else:
        flash("Failed to initialize Paystack payment.", "danger")
        return redirect(url_for('payment_page', order_id=order.id))
    
    
    
@app.route('/pay/stripe/<int:order_id>')
@login_required
def stripe_pay(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {'name': f'Order #{order.id}'},
                'unit_amount': int(order.total_amount * 100),
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('payment_success', order_id=order.id, _external=True),
        cancel_url=url_for('payment_page', order_id=order.id, _external=True),
    )
    return redirect(session.url)



@app.route('/pay/flutterwave/<int:order_id>')
@login_required
def flutterwave_pay(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)

    url = "https://api.flutterwave.com/v3/payments"
    headers = {
        "Authorization": f"Bearer {app.config['FLUTTERWAVE_SECRET_KEY']}",
        "Content-Type": "application/json"
    }
    data = {
        "tx_ref": f"order-{order.id}-{uuid.uuid4().hex[:8]}",
        "amount": order.total_amount,
        "currency": "USD",
        "redirect_url": url_for('payment_success', order_id=order.id, _external=True),
        "customer": {
            "email": current_user.email,
            "name": f"{current_user.first_name} {current_user.last_name}"
        },
        "customizations": {
            "title": "Peks World",
            "description": f"Payment for Order #{order.id}"
        }
    }

    response = requests.post(url, json=data, headers=headers)
    result = response.json()

    if result.get("status") == "success":
        return redirect(result["data"]["link"])
    else:
        flash("Flutterwave payment failed to initialize.", "danger")
        return redirect(url_for('payment_page', order_id=order.id))



@app.route('/payment-success/<int:order_id>')
@login_required
def payment_success(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    order.paid = True
    db.session.commit()
    flash(f"✅ Payment successful for Order #{order.id}", "success")
    return render_template('thank_you.html', order=order)








app.register_blueprint(user)
app.register_blueprint(admin)
app.register_blueprint(user_settings)



if __name__ == "__main__":
    with app.app_context():
        # db.drop_all()
        db.create_all()
        app.run(debug=True)

