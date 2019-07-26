from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from flask_moment import Moment
import jinja2
import jwt
import json

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
# jwt = JWTManager(app)

migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

def jwtToken(string):
	try:
		json_format = json.loads(string)
		encoded_jwt = jwt.encode(json_format, app.config['SECRET_JWT_KEY'], algorithm = 'HS256')
		return encoded_jwt

	except Exception as e:
		print(e)
		try:
			return jwt.encode(string, app.config['SECRET_JWT_KEY'], algorithm = 'HS256')
		except Exception as e:
			print(e)
			return string

		return string

def parseJwt(jwtToken):
	try:
		return jwt.decode(jwtToken, app.config['SECRET_JWT_KEY'], algorithms = ['HS256'])
	except Exception as e:
		print(e)
		return jwtToken

app.jinja_env.filters['zip'] = zip

from application import routes, models