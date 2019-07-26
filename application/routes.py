from flask import render_template, flash, redirect, url_for, request
from application import app, db, jwtToken, parseJwt
from flask_login import current_user, login_user, logout_user, login_required
from application.forms import UserForm, RegistrationForm
from application.models import User, Form
from werkzeug.urls import url_parse
from datetime import datetime
import traceback
import json

@app.route('/index', methods = ['POST', 'GET'])
@app.route('/', methods = ['POST', 'GET'])
def index():
	forms = current_user.forms.order_by(Form.timestamp.desc()).all()
	return render_template('index.html', forms = forms)

@app.route('/create', methods = ['POST', 'GET'])
def create_form():
	db.session.query(User).update({User.searched:False,User.selected:False})
	db.session.commit()
	return render_template('form_builder.html', title = "Create")

@app.route('/tokenize', methods = ['POST', 'GET'])
def tokenize_form():
	if(request.method == 'POST'):
		if not current_user.is_authenticated:
			return render_template('form_builder.html', title = "Create")

		fields = request.args.get('fields')
		title = request.args.get('title')
		print('title: ', title)
		# print("fields: ", fields)
		try:
			form = Form(user=current_user, title=title)
			json_form = '{"username":' + '\"' + current_user.username + '\"' + ',"id":' + '\"' + '%d' % current_user.id + '\"' +',"title":' + '\"' + title + '\"' + ',"fields":' + fields + '}'
			# print('JSON Passed: ', json_form)
			jwtTokenForm = jwtToken(json_form)
			# print("JWT Token: ", jwtTokenForm)
			url_root = request.url_root
			share_url = url_root + jwtTokenForm.decode("utf-8")
			print("Share URL: ", share_url)
			return redirect(url_for('select_users', share_url = share_url))
			# fields = json.loads(fields)
			# print("fields: ", fields)

			# for field in fields:

		except Exception as e:
			print(traceback.format_exc())

	return render_template('form_builder.html', title = "Create")

@app.route('/select_users',  methods = ['POST', 'GET'])
def select_users():
	try:
		if not current_user.is_authenticated:
			return redirect(url_for('index'))
	except:
		print(traceback.format_exc())

	if request.method == 'POST':
		try:
			share_url = request.args.get('share_url')
			search_input = request.form.get('search')
			selected_first = request.form.get('result0')
			saved_selected_users = [user.username for user in db.session.query(User).filter_by(selected = True).all()]
			selected = True if len(saved_selected_users) else False

			if search_input is not None:

				# print("Search input is valid")
				db.session.query(User).update({User.searched: False})
				results = db.session.query(User).filter(User.username.ilike('%{0}%'.format(search_input))).all()
				usernames = []
				for result in results:
					if result.username != current_user.username:
						result.searched = True
						usernames.append(result.username)
						db.session.add(result)

				db.session.commit()
				return render_template('select_users.html', results = usernames, searched = True, selected = selected, 
					selected_users = saved_selected_users, share_url = share_url, title = 'Search')

			else:
				# print("Selected: ", selected_indices)
				results = db.session.query(User).filter_by(searched = True).all()
				print("Results: ", results)

				# if(len(selected_indices) <= 0):
				# 	return render_template('select_users.html', results = results, searched = True, selected = selected, 
				# 		selected_users = saved_selected_users, share_url = share_url, title = 'Search')
		 
				selected_users = []
				nonZero = False
				for i in range(len(results)):
					check = request.form.get('result%d' % i)
					if check is not None:
						results[i].selected = True
						selected_users.append(results[i].username)
						db.session.add(results[i])

						# print("Selected: ", results[i])
						nonZero = True

					# selected_users = [results[i] for i in selected_indices]
				if not nonZero:
					return render_template('select_users.html', searched = False, selected = selected, 
						selected_users = selected_users, share_url = share_url, title = 'Search')


				saved_selected_users = saved_selected_users + selected_users
				selected = True
				print("Saved", saved_selected_users)					

				db.session.commit()
				return render_template('select_users.html', searched = False, selected = selected, 
					selected_users = saved_selected_users, share_url = share_url, title = 'Search')
		
		except:
			print("Error: ", traceback.format_exc())
			share_url = request.args.get('share_url')
			return render_template('select_users.html', searched = False, share_url = share_url, title = 'Search')

	else:
		share_url = request.args.get('share_url')
		return render_template('select_users.html', searched = False, share_url = share_url, title = 'Search')
	 
@app.route('/owner_view', methods = ['POST', 'GET'])
def owner_view():
	timestamp = request.args.get('timestamp')
	print("Timestamp", timestamp)
	return render_template('index.html', title = "View")

@app.route('/delete', methods = ['POST', 'GET'])
def delete():
	timestamp = request.args.get('timestamp')
	print("Timestamp", timestamp)
	return render_template('index.html', title = "Delete")

@app.route('/login', methods = ['POST', 'GET'])
def login():
	if(current_user.is_authenticated):
		return redirect(url_for('index'))

	userForm = UserForm()
	try:
		if request.method == 'POST':
			username = request.form['username']
			password = request.form['password']
			userForm.username['errors'] = []
			userForm.password['errors'] = []

			if(username == ''):
				userForm.username['errors'].append("Please enter your username or email")
			elif(password == ''):
				userForm.password['errors'].append("Please enter your password")
			else:
				user = db.session.query(User).filter_by(username=username).first()
				if user is None:
					userForm.username['errors'].append("Please enter a valid username or email")
				elif not user.check_password(password):
					userForm.username['errors'].append("Password is incorrect")
				else:
					remember_me = request.form.get('remember_me')
					if(remember_me is not None):
						login_user(user = user, remember = True)
					else:
						login_user(user = user,remember = False)

					next_page = request.args.get('next')
					if(not next_page or url_parse(next_page).netloc != ''):
						next_page = url_for('index')
					
					return redirect(next_page)

	except Exception as e:
		# print(e)
		print(traceback.format_exc())

	return render_template('login.html', form = userForm, title = 'Login')

@app.route('/register', methods = ['POST', 'GET'])
def register():

	if(current_user.is_authenticated):
		return redirect(url_for('index'))

	registrationForm = RegistrationForm()
	try:
		if request.method == 'POST':
			username = request.form['username']
			email = request.form['email']
			password = request.form['password']
			confirm_password = request.form['confirm_password']
			registrationForm.username['errors'] = []
			registrationForm.email['errors'] = []
			registrationForm.password['errors'] = []
			registrationForm.confirm_password['errors'] = []

			if(username == ''):
				registrationForm.username['errors'].append('Username is required')

			elif(email == ''):
				registrationForm.email['errors'].append('Email is required')

			elif(password == ''):
				registrationForm.password['errors'].append('This field is required')

			elif(confirm_password == ''):
				registrationForm.confirm_password['errors'].append('This field is required')

			elif email.find('@') <= 0 or email.find(' ') >= 0:
				# print("Index of @ = ", email.find('@'), "Index of ' ' = ", email.find(' '))
				registrationForm.email['errors'].append('Invalid Email ID')
			
			else:
				existing_user = db.session.query(User).filter_by(username=username).first()
				existing_email = db.session.query(User).filter_by(email=email).first()
				if(existing_user is not None):
					registrationForm.username['errors'].append('This username is already taken')
				elif(existing_email is not None):
					registrationForm.username['errors'].append('This email is already taken')
				elif(password != confirm_password):
					registrationForm.confirm_password['errors'].append('Passwords do not match')
				else:
					user = User(username=username, email=email)
					user.set_password(password)
					db.session.add(user)
					db.session.commit()
					flash("Successfully Reigstered")
					return redirect(url_for('login'))

	except Exception as e:
		# print(e)
		print(traceback.format_exc())

	return render_template('register.html', form = registrationForm, title = 'Register')

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))

if(__name__ == '__main__'):
	app.run(debug = True)

