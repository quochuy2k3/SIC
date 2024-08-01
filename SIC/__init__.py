import os
import cloudinary
import joblib
from dotenv import load_dotenv, dotenv_values
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_babel import Babel
from flask_cors import CORS

app = Flask(__name__)
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.secret_key = os.getenv('SECRET_KEY')

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

db = SQLAlchemy(app)
login = LoginManager(app)
Babel(app)
cors = CORS(app)

# VNPAY CONFIG
app.config['VNPAY_RETURN_URL'] = os.getenv('VNPAY_RETURN_URL')
app.config['VNPAY_PAYMENT_URL'] = os.getenv('VNPAY_PAYMENT_URL')
app.config['VNPAY_API_URL'] = os.getenv('VNPAY_API_URL')
app.config['VNPAY_TMN_CODE'] = os.getenv('VNPAY_TMN_CODE')
app.config['VNPAY_HASH_SECRET_KEY'] = os.getenv('VNPAY_HASH_SECRET_KEY')

# MOMO CONFIG
app.config['MOMO_ENDPOINT'] = os.getenv('MOMO_ENDPOINT')
app.config['MOMO_ACCESS_KEY'] = os.getenv('MOMO_ACCESS_KEY')
app.config['MOMO_SECRET_KEY'] = os.getenv('MOMO_SECRET_KEY')
app.config['MOMO_REDIRECT_URL'] = os.getenv('MOMO_REDIRECT_URL')
app.config['MOMO_IPN_URL'] = os.getenv('MOMO_IPN_URL')

# Load models
current_directory = os.path.dirname(os.path.abspath(__file__))
model_file_path = os.path.join(current_directory, 'models', 'RandomForestModel.joblib')
scale_file_path = os.path.join(current_directory, 'models', 'minmax_scaler.joblib')
scaler = joblib.load(scale_file_path)
loaded_model = joblib.load(model_file_path)
