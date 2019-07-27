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
import traceback

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
		# print(e)
		print(traceback.format_exc())
		try:
			return jwt.encode(string, app.config['SECRET_JWT_KEY'], algorithm = 'HS256')
		except Exception as e:
			print(traceback.format_exc())
			return string

		return string

def safeJwtToken(string):
	try:
		json_format = json.loads(string)
		encoded_jwt = jwt.encode(json_format, app.config['SECRET_JWT_KEY'], algorithm = 'HS256')
		split = encoded_jwt.decode("utf-8").split('.')
		encoded_jwt = split[0] + '.' + split[1] + app.config['SECRET_JWT_KEY_PROTECTION'] + '.' +split[2]
		return encoded_jwt

	except Exception as e:
		# print(e)
		print(traceback.format_exc())
		try:
			encoded_jwt = jwt.encode(string, app.config['SECRET_JWT_KEY'], algorithm = 'HS256')
		except Exception as e:
			print(traceback.format_exc())
			return string

		return string

def parseJwt(jwtToken):
	try:
		return jwt.decode(jwtToken, app.config['SECRET_JWT_KEY'], algorithms = ['HS256']), True
	except Exception as e:
		print(traceback.format_exc())
		return jwtToken, False

def parseSafeJwt(jwtToken):
	try:
		split = jwtToken.split('.')
		index = split[1].index(app.config['SECRET_JWT_KEY_PROTECTION'])
		encoded_jwt = split[0] + '.' +split[1][:index] + '.' + split[2]
		return jwt.decode(encoded_jwt, app.config['SECRET_JWT_KEY'], algorithms = ['HS256']), True
	except Exception as e:
		print(traceback.format_exc())
		return jwtToken, False

app.jinja_env.filters['zip'] = zip

from application import routes, models