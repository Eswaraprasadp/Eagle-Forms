from flask import render_template, flash, redirect, url_for, request, abort
from application import app, db, jwtToken, parseJwt, safeJwtToken, parseSafeJwt
from flask_login import current_user, login_user, logout_user, login_required
from application.forms import UserForm, RegistrationForm
from application.models import User, Form, Response, Invitation
from werkzeug.urls import url_parse
from datetime import datetime
import traceback
import json

@app.route('/index', methods = ['POST', 'GET'])
@app.route('/', methods = ['POST', 'GET'])
def index():
	return render_template('index.html')

@app.route('/<form_link>/viewform', methods = ['POST', 'GET'])
def view_form(form_link):
	try:
		if not current_user.is_authenticated:
			flash('Login to fill forms')
			return redirect(url_for('login'))

		form = db.session.query(Form).filter_by(form_link = form_link).first_or_404()
		title = form.get_title()
		fields, valid = form.get_fields()

		if not valid:
			print ("Invalid Fields: ", fields)
			abort(404)

		if current_user.is_filler(form):
			flash("You have already responded")
			return redirect(url_for('index'))

		if request.method == 'GET':
			print("Title: ", title, ", Fields: ", fields)
			return render_template('view_form.html', form_title = title, fields = fields, title = title)

		else:
			answers = []

			for field, i in zip(fields, range(len(fields))):

				answer_field = request.form.get('field%d' % i)
				print("Answer: ", answer_field)

				if answer_field is None:
					field['errors'] = ['This field is requied']
					return render_template('view_form.html', form_title = title, fields = fields, title = title)

				elif field['type'] == 'number':
					try:
						field['answer'] = float(answer_field)
						answers.append(field['answer'])
					except:
						print(traceback.format_exc())
						field['errors'].append("A number is expected")
						return render_template('view_form.html', form_title = title, fields = fields, title = title)
				else:
					field['answer'] = answer_field
					answers.append(field['answer'])

			response_json = '{"username":"' + current_user.username + '","answers":' + json.dumps(answers) + '}'
			print("Response JSON: ", response_json)
			response_jwt = safeJwtToken(response_json)
			current_user.add_filled(response = response_jwt, form = form)
			flash("Your responses were recorded")
			return redirect(url_for('index'))
	
	except:
		print(traceback.format_exc())
		abort(500)

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
			db.session.add(form)
			db.session.commit()
			json_form = '{"username":' + '\"' + current_user.username + '\"' + ',"id":' + '\"' + '%d' % form.id + '\"' +',"title":' + '\"' + title + '\"' + ',"fields":' + fields + '}'
			# print('JSON Passed: ', json_form)
			jwtTokenForm = jwtToken(json_form)
			# print("JWT Token: ", jwtTokenForm)
			form.form_link = jwtTokenForm.decode("utf-8")
			db.session.commit()
			return redirect(url_for('select_users', form_link = form.form_link))
			# fields = json.loads(fields)
			# print("fields: ", fields)

			# for field in fields:

		except Exception as e:
			print(traceback.format_exc())

	return render_template('form_builder.html', title = "Create")

@app.route('/select_users',  methods = ['POST', 'GET'])
def select_users():

	if not current_user.is_authenticated:
		return redirect(url_for('index'))

	share_url = request.args.get('share_url')

	if share_url is None:

		form_link = request.args.get('form_link')
		form = db.session.query(Form).filter_by(form_link = form_link).first_or_404()

		url_root = request.url_root
		share_url = url_root + form_link + "/viewform"

	print("Share URL: ", share_url)

	if request.method == 'POST':
		try:

			search_input = request.form.get('search')
			saved_selected_users = [user.username for user in db.session.query(User).filter_by(selected = True).all()]
			selected = True if len(saved_selected_users) else False
			submitted = request.args.get('submitted')
			submitted = True if submitted == 'true' else False

			if submitted:
				if not selected:
					return render_template('select_users.html', searched = False, selected = selected, 
						selected_users = saved_selected_users, share_url = share_url, title = 'Search')

				form_link = request.args.get('form_link')
				
				if share_url is None and form_link is None:
					abort(404)

				elif form_link is None:
					url_root = request.url_root
					root_index = share_url.index(request.url_root)
					view_index = share_url.index("/viewform")
					print("Root Index: ", root_index, "View Index: ", view_index)
					form_link = share_url[len(url_root) + root_index : view_index]

				print("Form link: ", form_link)				
				print("Saved selected users submitted: ", saved_selected_users)

				form = db.session.query(Form).filter_by(form_link = form_link).first_or_404()
				
				for user in saved_selected_users:
					u = db.session.query(User).filter_by(username = user).first_or_404()
					form.add_inviter(u)

				flash("Form URLs shared to " + ", ".join(saved_selected_users))
				db.session.query(User).update({User.searched:False,User.selected:False})
				db.session.commit()
				return redirect(url_for('index'))

			elif search_input is not None:

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
			return render_template('select_users.html', searched = False, share_url = share_url, title = 'Search')

	else:
		return render_template('select_users.html', searched = False, share_url = share_url, title = 'Search')
	 
@app.route('/<form_link>/responses', methods = ['POST', 'GET'])
def responses(form_link):
	form = db.session.query(Form).filter_by(form_link = form_link).first_or_404()
	if form.user.id != current_user.id:
		abort(404)

	responses = form.get_responses()
	fields, valid = form.get_fields()

	if not valid:
		abort(404)

	responses_data = []

	for response in responses:
		data, valid = parseSafeJwt(response.response)
		if not valid:
			abort(404)

		responses_data.append(data)

	return render_template('responses.html', title = "View Responses", fields = fields, responses = responses_data, form_title = form.get_title())

@app.route('/forms')
def forms():

	if not current_user.is_anonymous:
		flash("Login to view your forms")
		return redirect(url_for('login'))


	db.session.query(User).update({User.searched:False,User.selected:False})
	db.session.commit()

	forms = current_user.forms.order_by(Form.timestamp.desc()).all()

	return render_template('forms.html', forms = forms)

@app.route('/delete', methods = ['POST', 'GET'])
def delete():
	form_link = request.args.get('form_link')
	form = db.session.query(Form).filter_by(form_link = form_link).first_or_404()
	
	if form.user.id != current_user.id:
		abort(404)

	db.session.query(Response).filter_by(form = form).delete()
	db.session.delete(form)

	flash(form.title + " Deleted")

	db.session.commit()
	return render_template('index.html', title = "Delete")

@app.route('/delete_notification', methods = ['POST', 'GET'])
def delete_notification():
	try:
		if not current_user.is_authenticated:
			flash("Login to delete notifications")
			return redirect(url_for('login'))

		form_link = request.args.get('form_link')
		invitation = User.get_invitation(form_link)
		if invitation is None:
			abort(404)

		title = invitation.form.title

		current_user.delete_invitation(invitation)

		flash("Invitation for " + title + " deleted")

		return redirect(url_for('index'))

	except Exception as e:
		print(traceback.format_exc())
		return redirect(url_for('index'))

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

@app.errorhandler(500)
def internal_server_error(error):
	return "Internal Server Error\nStatus Code: 500", 500

@app.errorhandler(404)
def not_found_error(error):
	return "Page not found\nStatus Code: 404", 404

if(__name__ == '__main__'):
	app.run(debug = True)

