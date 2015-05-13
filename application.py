import random, string, httplib2, json, requests

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response
from flask import session as login_session

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

from database_setup import Base, User, Category, Item

app = Flask(__name__)

# Connect to database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Functions to handle authentication
@app.route('login')
def showLogin():
    return "Login page"


@app.route('/gconnect')
def gconnect():
    return "Controller for handle ajax for google oauth"


@app.route('/gdisconnect')
def gdisconnect():
    return "Logoff google oauth"


@app.route('/fbconnect')
def fbconnect():
    return "Controller for handle ajax for facebook oauth"


@app.route('/fbdisconnect')
def fbdisconnect():
    return "Logoff facebook oauth"


@app.route('/disconnect')
def disconnect():
    return "Logout page"


# Functions to JSON API
@app.route('category/JSON')
def categoriesJSON():
    return "All categories as JSON"


@app.route('category/JSON/<int:category_id>')
def categoryJSON(category_id):
    return "JSON category object"


@app.route('category/JSON/items/')
def itemsCategoryJSON():
    return "All items as JSON"


@app.route('category/JSON/items/<int:category_id>')
def itemsCategoryJSON(category_id):
    return "All items in category as JSON"


@app.route('category/JSON/items/<int:category_id>/<int:item_id>')
def itemsCategoryJSON(category_id, item_id):
    return "Specific item in category as JSON"


@app.route('/catalog.json')
def allCatalogJSON():
    return "Show items and categories as json"


# Main CRUD functions
@app.route('/')
def showLatest():
    return "Show latest added items"


@app.route('catalog/<string:category_name>/items')
def showItems(category_name):
    return "Show items in category"


@app.route('catalog/<string:category_name>/<string:item_name>')
def showItem(category_name, item_name):
    return "Show one item in category"


@app.route('catalog/<string:item_name>/edit')
def editItem(item_name):
    return "Edit item page"


@app.route('catalog/<string:item_name>/delete')
def deleteItem(item_name):
    return "Delete item page"


if __name__ == 'main':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)