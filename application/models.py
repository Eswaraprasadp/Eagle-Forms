from application import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from application import login
from flask_login import UserMixin

@login.user_loader
def load_user(id):
	user = User.query.get(int(id))
	if(user):
		return user
	else:
		return None

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)
	password_hash = db.Column(db.String(128))
	selected = db.Column(db.Boolean, default = False)
	searched = db.Column(db.Boolean, default = False)
	forms = db.relationship('Form', backref='user', lazy = 'dynamic')

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<User {}>'.format(self.username) 

class Form(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	title = db.Column(db.String(140))
	timestamp = db.Column(db.DateTime, index = True, default = datetime.utcnow)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	def __repr__(self):
 		return '<Form {}>'.format(self.title) 

selected = db.Table('selected',
	db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)