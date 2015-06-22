####################################
      HOW TO RUN APPLICATION
####################################
Requirements:
1. Python 2.7.6 with Standard Library
2. Flask 0.10.1
3. sqlalchemy 1.0.4
4. oauth2client 1.4.7
5. httlib2 0.9
6. Flask-SeaSurf 0.2.0

FILES IN PACKAGE:
application.py -- python script with flask main application
itemcatalog.db -- sqlite database for item catalog
database_setup.py -- pathon script for sqlalchemy database schema
initData.py -- python script to polulate database with sample data
static/css/styles.css -- css style templates
static/css/bootsrap* -- bootsrap framework styles
static/fonts/* -- bootsrap framework fonts
static/js/bootsrap.min.js -- bootsrap framework scripts
static/js/jquery-2.1.1.min.js -- jQuery library
templates/add_item.html -- template for item add view
templates/catalog.html -- template for catalog and category overview
templates/delete_item.html -- template for item delete view
templates/edit_item.html -- template for item edit view
templates/main.html -- base html for all templates
templates/login.html -- template for login view
templates/item.html -- template for item view
templates/loggedindex.html -- template for showLatest view if user isn't logged
templates/publicindex.html -- template for showLatest view if user was logged
templates/publicitems.html -- template for items in category view

STEPS:
1. Copy all files to your computer
2. Run terminal (Mac\Linux) or command prompt(Windows)
3. Install all packages from requirements section by pip install
4. Run application: python application.py
5. Web interface can be accessed by http://localhost:8000 from local machine
6. That's all :)

RUN ON Vagrant VM:
1. Copy all files to your vagrant directory in your local machine
2. start up vagrant VM by running: vagrant up
3. connect to your vagrant VM: vagrant ssh
4. Install all packages from requirements section by pip install in your vagrant VM
5. in your vm in vagrant directory go to application directory (for example: cd /vagrant/ItemCatalog)
6. App can be accessed by http://localhost:8000 from local machine
7. For stop application press CTRL+C


RESET DATABASE:
1. delete itemcatalog.db
2. run database_setup.py (python database_setup.py)
3. run initData.py (python initData.py)


API ENDPOINT:
1. Api endpoint can be accessed by http://localhost:8000/category/JSON/items/
It return items by category in JSON format

####################################