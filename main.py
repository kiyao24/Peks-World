from flask import Flask, Blueprint
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from model import Users,db
from flask_migrate import Migrate
from datetime import datetime
# import stripe
import os






app = Flask(__name__)
# user = Blueprint('auth', __name__, template_folder='templates')
admin = Blueprint('admin', __name__)
# defaulthomepage = Blueprint('defaulthomepage', __name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['PAYSTACK_SECRET_KEY'] = os.getenv('PAYSTACK_SECRET_KEY')
# app.config['STRIPE_SECRET_KEY'] = os.getenv("STRIPE_SECRET_KEY")
# app.config['FLUTTERWAVE_SECRET_KEY'] = os.getenv("FLUTTERWAVE_SECRET_KEY")
# app.config['FLUTTERWAVE_PUBLIC_KEY'] = os.getenv("FLUTTERWAVE_PUBLIC_KEY")

# stripe.api_key = app.config['STRIPE_SECRET_KEY']


user_settings = Blueprint('settings', __name__, url_prefix='/settings')  # New blueprint for user settings

user_notifications = {
    1: [
        {"id": 1, "message": "Your order #123 has shipped!", "read": False},
        {"id": 2, "message": "New promo: 10% off all items!", "read": False}
    ]
}

db.init_app(app)

migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.login'
login_manager.login_message_category = 'info'  

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))




