from application import app, db, moment
from application.models import User, Form, Response, Invitation

@app.shell_context_processor
def make_shell_context():
	return {'db': db, 'User': User, 'users': User.query.all(), 'moment': moment, 'Form' : Form, 'Response' : Response, 'Invitation' : Invitation}