from application.models import User

class UserForm:
	username = {'label' : 'Username', 'type' : 'stringField', 'errors' : [], 'value' : ''}
	password = {'label' : 'Password', 'type' : 'passwordField', 'errors' : [], 'value' : ''}
	remember_me = {'label' : 'Remember Me', 'type' : 'booleanField'}
	submit = {'label' : 'Submit', 'type' : 'submitField'}

class RegistrationForm:
	username = {'label' : 'Username', 'type' : 'stringField', 'errors' : [], 'value' : ''}
	email = {'label' : 'Email', 'type' : 'stringField', 'errors' : [], 'value' : ''}
	password = {'label' : 'Password', 'type' : 'passwordField', 'errors' : [], 'value' : ''}
	confirm_password = {'label' : 'Confirm Password', 'type' : 'passwordField', 'errors' : []}
	submit = {'label' : 'Submit', 'type' : 'submitField', 'errors' : []}

