from application import db, parseJwt, jwtToken, safeJwtToken, parseSafeJwt
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from application import login
from flask_login import UserMixin
import traceback

@login.user_loader
def load_user(id):
	user = User.query.get(int(id))
	if(user):
		return user
	else:
		return None

class Response(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	form_id = db.Column(db.Integer, db.ForeignKey('form.id'))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	response = db.Column(db.String(200))

	form = db.relationship('Form',
		backref = db.backref('responses', lazy = 'joined'),
		lazy = 'joined'
	)

	user = db.relationship('User',
		backref = db.backref('filled_forms', lazy = 'joined'),
		lazy = 'joined'
	)

	def __repr__(self):
		return '<Response user:{}, form:{}, response:{}>'.format(self.user, self.form, self.response)

class Invitation(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	form_id = db.Column(db.Integer, db.ForeignKey('form.id'))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	timestamp = db.Column(db.DateTime, index = True, default = datetime.utcnow)

	form = db.relationship('Form',
		backref = db.backref('sent_invitations', lazy = 'joined'),
		lazy = 'joined'
	)

	user = db.relationship('User',
		backref = db.backref('recieved_invitations', lazy = 'joined'),
		lazy = 'joined'
	)

	def __repr__(self):
		return '<Invitaion user:{}, form:{}>'.format(self.user, self.form)

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

	def is_filler(self, form):
		return db.session.query(Response).filter((Response.user_id == self.id) & (Response.form_id == form.id)).count() > 0

	def add_filled(self, form, response):
		if not self.is_filler(form):
			response = Response(response = response, user = self, form = form)
			db.session.add(response)
			db.session.commit()

	def is_invited(self, form):
		return db.session.query(Invitation).filter((Invitation.user_id == self.id) & (Invitation.form_id == form.id)).count() > 0

	def add_invitation(self, form):
		if not self.is_invited(form):
			invitation = Invitation(user = self, form = form)
			db.session.add(invitation)
			db.session.commit()

	def delete_invitation(self, invitation):
		if invitation.user_id == self.id:
			db.session.delete(invitation)
			db.session.commit()
			return True

		return False

	def get_invitation(form_link):
		form = db.session.query(Form).filter_by(form_link = form_link).first()
		if form is None:
			return None

		invitation = db.session.query(Invitation).filter((Invitation.user_id == form.id) & (Invitation.form_id == form.id)).first()
		return invitation

	def __repr__(self):
		return '<User {}>'.format(self.username) 

class Form(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	title = db.Column(db.String(140))
	timestamp = db.Column(db.DateTime, index = True, default = datetime.utcnow)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	form_link = db.Column(db.String(300), index = True)
	
	def is_filled(self, user):
		return db.session.query(Response).filter((Response.form_id == self.id) & (Response.user_id == user.id)).count() > 0

	def add_filler(self, user, response):
		if not self.is_filled(user):
			response = Response(response = response, user = user, form = self)
			db.session.add(response)
			db.session.commit()

	def is_inviter(self, user):
		return db.session.query(Invitation).filter((Invitation.form_id == self.id) & (Invitation.user_id == user.id)).count() > 0

	def add_inviter(self, user):
		if not self.is_inviter(user):
			invitation = Invitation(user = user, form = self)
			db.session.add(invitation)
			db.session.commit()

	def get_responses(self):
		return self.responses

	def get_fields(self):
		data, valid = parseJwt(self.form_link)
		if not valid:
			return None, False

		elif data['title'] != self.title:
			return data['fields'], False

		return data['fields'], True

	def get_title(self):
		return self.title

	def __repr__(self):
 		return '<Form {}>'.format(self.title) 
