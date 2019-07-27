# Eagle Forms
## Description
A Form Builder

## Requirements
- Python
- pip
- Virtual environment


## Installation and Usage
Open Command Prompt and Change the directory to the cloned repository.

### Creating Virtual Environment
First create a virtual environment. <br/>
For Python version 3 and higher:
```
$ python -m venv venv
```
For lower versions,
```
$ virtual venv
```
### Activating Virtual Environment
For Windows, run the following commands
```
$ venv\Scripts\activate
``` 
For Linux, Mac and other Operating Systems, run the following commands
```
$ venv/Scripts/activate
``` 
### Installing required Python libraries
Install the required Python libraries from requirements.txt via the following command:
```
$ pip install -r requirements.txt
```
If the above command gives errors, then the libraries are to installed via pip seperately. The libraries are
- flask
- flask-migrate
- flask-session
- PyJwt
- flask-sqlalchemy
- flask-moment
- flask-bootstrap

### Initializing database
Database is created and updated by the following commands:
```
$ flask db init
$ flask db migrate
$ flask db upgrade
```

### Run The App
For running the app, use:
```
$ flask run
```
Alternatively the following can also be used,
```
$ python -m flask run
```
If there are no errors and app starts running, the website can be visited from
```
http://127.0.0.1:5000/
```
or
```
localhost:5000
```
on a browser.
