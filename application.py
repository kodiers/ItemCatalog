import random, string, httplib2, json, requests

from functools import wraps

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response
from flask import session as login_session
from flask.ext.seasurf import SeaSurf

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError, AccessTokenCredentials

from database_setup import Base, User, Category, Item

app = Flask(__name__)
csrf = SeaSurf(app)

# Connect to database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Load google secrets
CLIENT_ID = json.loads(open('client_secret.json', 'r').read())['web']['client_id']

# User helper functions
def createUser(login_session):
    """
    Create user from login_session data and return user's id
    """
    newUser = User(name=login_session['username'], email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    Return user object
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    Return user id or None
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Functions to handle authentication
@app.route('/login')
def showLogin():
    """
    Show login page and generate session.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Authenticate through Google OAuth API function.
    Get post-request object.
    Return HTML with callback JS function
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:
        # Upgrade authorization code into credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error  in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID doesn't match app's."), 401)
        print("Token's client ID doesn't match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store access token in session for later use
    # Store just token (for resolve JSON error bug in Flask)
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get credentials from session
    credentials = AccessTokenCredentials(login_session['credentials'], 'user-agent-value')
    login_session['provider'] = 'google'
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    # if users exists, doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@csrf.exempt
@app.route('/gdisconnect')
def gdisconnect():
    """
    Revoke user token and reset login_session
    """
    # Use AccessTokenCredentials for fix bug in Flask
    credentials = AccessTokenCredentials(login_session['credentials'], 'user-agent-value')
    if credentials is None:
        response = make_response(json.dumps("Current user not connected."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET to revoke token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected!'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@csrf.exempt
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    Handle AJAX callback from login page
    And authenticate through Facebook API
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    app_id = json.loads(open('fbclientsecrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fbclientsecrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % \
          (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.2/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.2/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split('=')[1]
    login_session['access_token'] = stored_token

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    flash("Now logged in as %s" % login_session['username'])
    return output


@csrf.exempt
@app.route('/fbdisconnect')
def fbdisconnect():
    """
    Revoke user's token if he's logged from through facebook API
    """
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % (facebook_id)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]


@csrf.exempt
@app.route('/disconnect')
def disconnect():
    """
    Logout user and delete login_session's objects
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            # Disconect from google
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            # Disconnect from facebook
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out")
        return redirect('')
    else:
        flash("You were not logged in to begin with")
        return redirect(url_for('showLatest'))


# Functions to JSON API

@app.route('/category/JSON/items/')
def itemsJSON():
    """
    Return items and categories as JSON list
    """
    categories = session.query(Category).all()
    categories_list = []
    for category in categories:
        list = []
        items = session.query(Item).filter_by(category_id=category.id)
        for item in items:
            list.append({"title" : item.name, "id" : item.id, "description" : item.description,
                         "cat_id": item.category_id})
        categories_list.append({"id": category.id, "name": category.name, "Items": list})
    return jsonify({"Category":categories_list})


# Login required decorator
# Check if user logged in else - redirect to login page
def login_requred(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function



# Main CRUD functions

@app.route('/')
def showLatest():
    """
    Show all categories and ten latest added items
    """
    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.created_date).slice(0, 10)
    if 'username' not in login_session:
        return render_template('publicindex.html', categories=categories, items=items)
    else:
        return render_template('loggedindex.html', categories=categories, items=items)


@app.route('/catalog/<int:category_id>/items')
def showItems(category_id):
    """
    Show item in specific category
    :param category_name: name of category
    """
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('publicitems.html', category=category, categories=categories, items=items)


@app.route('/catalog/<string:category_name>/<int:item_id>')
def showItem(category_name, item_id):
    """
    Return one item in category.
    :param category_name: category name
    :param item_name: item name
    """
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(id=item_id, category_id=category.id).one()
    creator = getUserInfo(item.user_id)
    return render_template('item.html', category=category, categories=categories, item=item, creator=creator)


@app.route('/catalog/add', methods=['GET', 'POST'])
@login_requred
def addItem():
    """
    Create new item
    """
    # if 'username' not in login_session:
    #     return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=request.form['category']).one()
        old_items = session.query(Item).filter_by(category_id=category.id, name=request.form['title']).all()
        if old_items == []:
            new_item = Item(name = request.form['title'], user_id = login_session['user_id'],
                            description=request.form['description'], category_id=category.id, category=category)
            session.add(new_item)
            session.commit()
            flash('New item %s successfully created' % new_item.name)
            return redirect(url_for('showLatest'))
        else:
            flash('Item with this name %s exist. Try again!' % request.form['title'])
            return redirect(url_for('showLatest'))
    else:
        categories = session.query(Category).all()
        return render_template('add_item.html', categories=categories)


@app.route('/catalog/<int:item_id>/edit', methods=['GET', 'POST'])
@login_requred
def editItem(item_id):
    """
    Edit item page. Show edit item apge and process editing.
    :param item_name: name of item to edit
    """
    # if 'username' not in login_session:
    #     return redirect('/login')
    editedItem = session.query(Item).filter_by(id=item_id).one()
    categories = session.query(Category).all()
    if login_session['user_id'] != editedItem.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['title']:
            editedItem.name = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            category = session.query(Category).filter_by(name=request.form['category']).one()
            editedItem.category_id = category.id
            editedItem.category = category
        session.add(editedItem)
        session.commit()
        flash('Item edited successfully!')
        return redirect(url_for('showLatest'))
    else:
        return render_template('edit_item.html', categories=categories, item=editedItem)


@app.route('/catalog/<int:item_id>/delete' , methods=['GET', 'POST'])
@login_requred
def deleteItem(item_id):
    """
    Delete item page. End process deleting of item.
    :param item_name: name of item to delete
    """
    # if 'username' not in login_session:
    #     return redirect('/login')
    deletedItems = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != deletedItems.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(deletedItems)
        session.commit()
        flash('Item deleted successfully!')
        return redirect(url_for('showLatest'))
    else:
        return render_template('delete_item.html', item=deletedItems)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)