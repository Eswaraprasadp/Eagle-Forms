from application import app, db, moment
from application.models import User, Form
import jwt
import json

@app.shell_context_processor
def make_shell_context():
	return {'db': db, 'User': User, 'users': User.query.all(), 'moment': moment, 'Form' : Form, 'eswar' : db.session.query(User).filter_by(username='eswar').first()}