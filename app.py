# manage database and users
import sqlite3
# import the Table class
from sqlalchemy import Table, create_engine
from sqlalchemy.sql import select
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, current_user, LoginManager, UserMixin

# The data.sqlite file is the database and stores the username, 
# password, and email address in the Users table. To protect user 
# passwords, the password will be hashed using the werkzeug library. 
# Werkzeug is an advanced web server gateway interface (WSGI) utilities library.


# manage password hashing
from werkzeug.security import generate_password_hash, check_password_hash

# use to config server
import warnings
import os
import configparser

# dash dependencies
import dash_core_components as dcc
import dash_html_components as html
import dash
from dash.dependencies import Input, Output, State


warnings.filterwarnings("ignore")


# connect to the database
conn = sqlite3.connect('data.sqlite')
engine = create_engine('sqlite:///data.sqlite')
# create the object and configure the application later
db = SQLAlchemy()
# some notes on SQLALchemy: https://www.sqlalchemy.org/features.html


# config stores info about configuration
config = configparser.ConfigParser()


# create users class for interacting with users table
class Users(db.Model):
    # db = SQLAlchemy() as defined above
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable = False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
# note there isn't __init__() method, we can't create new Users with Users(username=xxx, email=yyy, password=zzz)
# we create new Users with Table() defined in the following line. 

# Table is a class imported from sqlalchemy
# User.metadata is https://docs.sqlalchemy.org/en/14/core/metadata.html#sqlalchemy.schema.MetaData 
Users_tbl = Table('users', Users.metadata)


# function to create table using Users class
def create_users_table():
    Users.metadata.create_all(engine)
# create_all(engine) Create all tables stored in this metadata.


#create the table
create_users_table()

# instantiate dash app
app = dash.Dash(__name__)
server = app.server
# ????
app.config.suppress_callback_exceptions = True


# config the server to interact with the database. Secret Key is used for user sessions
server.config.update(
    # os.urandom is used to generate the SECRET_KEY.
    SECRET_KEY=os.urandom(12),
    # the location of our database, /// means relative path, //// means absolute path
    SQLALCHEMY_DATABASE_URI='sqlite:///data.sqlite',
    SQLALCHEMY_TRACK_MODIFICATIONS=False)


db.init_app(server)
# 


# The login manager lets the Dash app load a user from an ID and validate the user.
login_manager = LoginManager()
# Use the LoginManager class to allow the Dash app to work with Flask-Login. 
# Flask-Login uses sessions for authentication by default. 
# This means the configuration must include a secret key. 
# That is why SECERET_KEY is set in the previous section.


# This provides default implementations for the methods that Flask-Login 
# expects user objects to have
login_manager.init_app(server)
login_manager.login_view = '/login'


# User as base. Create User class with UserMixin
class Users(UserMixin, Users):
    pass

create = html.Div([ html.H1('Create User Account')
        , dcc.Location(id='create_user', refresh=True)
        , dcc.Input(id="username"
            , type="text"
            , placeholder="user name"
            , maxLength =15)
        , dcc.Input(id="password"
            , type="password"
            , placeholder="password")
        , dcc.Input(id="email"
            , type="email"
            , placeholder="email"
            , maxLength = 50)
        , html.Button('Create User', id='submit-val', n_clicks=0)
        # n_clicks: an integer that represents the number of times that this element has been clicked on.
        , html.Div(id='container-button-basic')
        # Div 'container-button-basic' describes the login hyperlink
    ])
#end div
    

login =  html.Div([dcc.Location(id='url_login', refresh=True)
            , html.H2('''Please log in to continue:''', id='h1')
            , dcc.Input(placeholder='Enter your username',
                    type='text',
                    id='uname-box')
            , dcc.Input(placeholder='Enter your password',
                    type='password',
                    id='pwd-box')
            , html.Button(children='Login',
                    n_clicks=0,
                    type='submit',
                    id='login-button')
            , html.Div(children='', id='output-state')
        ]) 
#end div
        

success = html.Div([dcc.Location(id='url_login_success', refresh=True)
            , html.Div([html.H2('Login successful.')
                    , html.Br()
                    , html.P('Select a Dataset')
                    , dcc.Link('Data', href = '/data')
                ]) #end div
            , html.Div([html.Br()
                    , html.Button(id='back-button', children='Go back', n_clicks=0)
                ]) #end div
        ]) #end div
    

data = html.Div([dcc.Dropdown(
                    id='dropdown',
                    options=[{'label': i, 'value': i} for i in ['Day 1', 'Day 2']],
                    value='Day 1')
                , html.Br()
                , html.Div([dcc.Graph(id='graph')])
            ]) #end div
    

failed = html.Div([ dcc.Location(id='url_login_df', refresh=True)
            , html.Div([html.H2('Log in Failed. Please try again.')
                    , html.Br()
                    , html.Div([login])
                    , html.Br()
                    , html.Button(id='back-button', children='Go back', n_clicks=0)
                ]) #end div
        ]) #end div
    

logout = html.Div([dcc.Location(id='logout', refresh=True)
        , html.Br()
        , html.Div(html.H2('You have been logged out - Please login'))
        , html.Br()
        , html.Div([login])
        , html.Button(id='back-button', children='Go back', n_clicks=0)
    ])#end div
    


# describes what the page looks like
app.layout= html.Div([
            html.Div(id='page-content', className='content')
            ,  dcc.Location(id='url', refresh=False)
            # The dcc.Location component represents the location or address bar in your web browser. 
            # Through its href, pathname, search and hash properties you can access different portions of the url 
            # that the app is loaded on.
        ])


# callback to reload the user object. A callback to the login_manager is needed to 
# complete the login processes. This callback will go with the rest of the Dash Callbacks.
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# decide on which page to display
@app.callback(
    Output('page-content', 'children')
    , [Input('url', 'pathname')])
    # 
def display_page(pathname):
    if pathname == '/':
        return create
    elif pathname == '/login':
        return login
    elif pathname == '/success':
        if current_user.is_authenticated:
            return success
        else:
            return failed
    elif pathname =='/data':
        if current_user.is_authenticated:
            return data
    elif pathname == '/logout':
        if current_user.is_authenticated:
            logout_user()
            return logout
        else:
            return logout
    else:
        return '404'


#set the callback for the dropdown interactivity
@app.callback([Output('graph', 'figure')], [Input('dropdown', 'value')])
def update_graph(dropdown_value):
    if dropdown_value == 'Day 1':
        return [{'layout': {'title': 'Graph of Day 1'}
                , 'data': [{'x': [1, 2, 3, 4]
                    , 'y': [4, 1, 2, 1]}]}]
    else:
        return [{'layout': {'title': 'Graph of Day 2'}
                ,'data': [{'x': [1, 2, 3, 4]
                    , 'y': [2, 3, 2, 4]}]}]


# Using a callback, the input is written to the database. The input is stored using the dash dependency State. 
@app.callback(
   [Output('container-button-basic', "children")]
    , [Input('submit-val', 'n_clicks')]
    , [State('username', 'value'), State('password', 'value'), State('email', 'value')])
    # The State allows the values to be input without firing the callback until the Create User button is pushed.
def insert_users(n_clicks, un, pw, em):
    hashed_password = generate_password_hash(pw, method='sha256')
    if un is not None and pw is not None and em is not None:
        ins = Users_tbl.insert().values(username=un,  password=hashed_password, email=em,)
        conn = engine.connect()
        conn.execute(ins)
        conn.close()
        return [login]
        # changes the 'Already have an account ?' Div into Login Div
    else:
        return [html.Div([html.H2('Already have a user account?'), dcc.Link('Click here to Log In', href='/login')])]


@app.callback(
    Output('url_login', 'pathname')
    , [Input('login-button', 'n_clicks')]
    , [State('uname-box', 'value'), State('pwd-box', 'value')])
    # The State allows the values to be input without firing the callback until the Login button is pushed.
def successful(n_clicks, input1, input2):
    user = Users.query.filter_by(username=input1).first()
    # find all users in my table with username = input1, grab the first entry
    if user:
        if check_password_hash(user.password, input2):
        # check_password_hash() is an imported function 
            login_user(user)
            return '/success'
            # 
        else:
            pass
    else:
        pass
    
@app.callback(
    Output('output-state', 'children')
    , [Input('login-button', 'n_clicks')]
    , [State('uname-box', 'value'), State('pwd-box', 'value')])
def update_output(n_clicks, input1, input2):
    if n_clicks > 0:
        user = Users.query.filter_by(username=input1).first()
        # find all users in my table with username = input1, grab the first entry
        if user:
            if check_password_hash(user.password, input2):
                return ''
            else:
                return 'Incorrect password or username doesn\'t exist'
        else:
            return 'Incorrect username'
    else:
        return ''
        
        
@app.callback(Output('url_login_success', 'pathname'), [Input('back-button', 'n_clicks')])
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return '/'
        
        
@app.callback(Output('url_login_df', 'pathname'), [Input('back-button', 'n_clicks')])
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return '/'
        
# Create callbacks
@app.callback(Output('url_logout', 'pathname'), [Input('back-button', 'n_clicks')])
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return '/'

if __name__ == '__main__':
    app.run_server(debug=True)