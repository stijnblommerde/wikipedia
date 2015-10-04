# libraries
import webapp2
import os
import jinja2
import utils
import time
from google.appengine.ext import db
from google.appengine.api import memcache

# constants
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

# setup for using templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True) 

## handlers ##

# super class
class BaseHandler(webapp2.RequestHandler):

    # shorthand function for response.out.write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # render a template
    def render_str(self, template, **params):
        params['user'] = self.user #add user as default argument
        t = jinja_env.get_template(template)
        return t.render(params)

    # def render(self, template, **kw):
    #     self.response.out.write(self.render_str(template, **kw))

    def render(self, template, *a, **kw):
        self.response.out.write(self.render_str(template, *a, **kw))

    def set_secure_cookie(self, name, value):
        cookie_value = utils.make_secure_value(value)
        self.response.headers.add_header("Set-Cookie", "%s=%s; Path=/" % (name, cookie_value))

    def get_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return cookie_value and utils.check_secure_value(cookie_value)

    def __init__(self, request, response):
        webapp2.RequestHandler.initialize(self, request, response)

        #store current user
        user_id = self.get_secure_cookie('user_id')
        self.user = user_id and User.by_id(int(user_id))

#authorization handlers
class SignupHandler(BaseHandler):
    def get(self):
        self.render("signup.html", authorize=True)

    def post(self):

        # get user input
        input_username = self.request.get('username')
        input_password = self.request.get('password')
        input_verify = self.request.get('verify')
        input_email = self.request.get('email')
        signup = True;

        valid_input, validate_params = validate_form(signup, input_username, input_password, input_verify, input_email)
        matching_usernames, matching_param = compare_usernames(input_username)

        # user exists
        if matching_usernames:
            self.render("signup.html", authorize=True, **matching_param)

        # invalid input
        elif not valid_input:
            self.render("signup.html", authorize=True, **validate_params)

        # user does not exist and valid input
        else:

            # create user
            user = User.signup(input_username, input_password, input_email)
            user.put()

            #delete tuples from table
            #db.delete(users)

            user_id = user.key().id()
            cookie_value = self.get_secure_cookie(user_id)

            # cookie exists
            if cookie_value:

                # secure cookie: redirect to front page
                if check_secure_value(cookie_value):
                    self.redirect('/')

                # insecure cookie: redirect to signup page
                else:
                    self.redirect('/signup')

            # cookie does not exist, create cookie and redirect to front page
            else:
                if user_id:
                    self.set_secure_cookie('user_id', str(user_id))
                    self.redirect('/')

class LoginHandler(BaseHandler):

    def get(self):

        # login with cookie if cookie exists
        cookie_value = self.request.cookies.get("user_id")
        if cookie_value and utils.check_secure_value(cookie_value):
            self.redirect('/')
        else:
            self.render("login.html", authorize=True)
    
    def post(self):

        # get user input
        input_username = self.request.get('username')
        input_password = self.request.get('password')

        # validate user input
        valid_input, validate_params = validate_form(False, input_username, input_password)

        # invalid username or password
        if not valid_input:
            self.render('login.html', authorize=True, **validate_params)
            return;

        # check if user exists
        exists = user_exists(input_username)
        if not exists:
            self.render('login.html', authorize=True, error_login="User does not exist in database")
            return;

        # valid username and password and username exists in database
        # create cookie for returned entry
        user = User.by_name(input_username)
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

        # show front page
        self.redirect('/')

class LogoutHandler(BaseHandler):
    def get(self):

        # clear cookie
        self.response.headers.add_header("Set-Cookie", "%s=%s; Path=/" % ('user_id', ""))
        
        #redirect to front page
        self.redirect('/')

class EditHandler(BaseHandler):
    
    # get method triggered when you click edit button
    def get(self, path):
        print "enter edithandler"

        # get most recent page of path
        page = Page.by_path(path)

        # get version from url 
        version = self.request.get('v')

        # get version from cache
        if not version:
            print 'got version from cache'
            version = memcache.get('version')

        # update page
        if version:
            page = Page.by_version(path, int(version))

        # render (empty or prefilled) page
        self.render('edit.html', page=page, path=path, main=True)

    # post triggered when you click save button
    def post(self, path):

        # get edited content from user
        content = self.request.get('content')

        # store new content in database and version in memcache
        if path and content:
            page = Page.by_path(path)
            if not page: 
                version = 1
            else: 
                version = page.version + 1
            page = Page.make_page(path, content, version)
            page.put()
            time.sleep(0.5)
            memcache.set('version', version)

        # redirect to new page
        self.redirect(path)

class WikiPageHandler(BaseHandler):
    
    def get(self, path):
        print "enter wikihandler"

        # debugging: delete all pages
        #db.delete(Page.all())

        # for given path: get newest page
        page = Page.by_path(path)

        # for given path: get version
        version = self.request.get('v')
        if version:
            page = Page.by_version(path, int(version))

            #store version in memcache
            memcache.set('version', version)

        # automatically create a homepage
        if not page and path == '/':
            page = Page.make_page('/', 'Blank page', 1)
            page.put()
            time.sleep(0.5)

        # page does not exist, redirect to edit
        if not page:
            self.redirect('/_edit' + path)
        else:
            # page exists, render page
            self.render('page.html', content=page.content, path=path, page=page, main=True)

class HistoryHandler(BaseHandler):

    def get(self, path):
        print "enter historyhandler"

        #get all versions of page
        pages = Page.all().filter('path =', path).order('-created')

        #store most recent page in cache
        page = Page.by_path(path)
        memcache.set('version', page.version)
        
        self.render('history.html', path=path, pages=pages, history=True)

## models ##

class User(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = get_users_key())

    @classmethod
    def by_name(cls, username):
        user = User.all().filter('username =', username).get()
        return user

    @classmethod
    def signup(cls, username, password, email = None):
        password_hash = utils.make_pw_hash(username, password)
        return User(parent = get_users_key(),
                    username = username,
                    password_hash = password_hash,
                    email = email)

class Page(db.Model):
    path = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    version = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return Page.get_by_id(uid, parent = get_pages_key())   

    # get page by name
    @classmethod
    def by_path(cls, path):
        page = Page.all().filter('path =', path).order('-created').get()
        return page

    @classmethod
    def make_page(cls, path, content, version):
        return Page(parent=get_pages_key(), path=path, content=content, version=version)     

    @classmethod
    def by_version(cls, path, version):
        page = Page.all().filter('path =', path).filter('version =', version).get()
        return page        

## helper functions ##

def validate_form(signup, input_username, input_password, input_verify=None, input_email=None):
    """
    params: 
     - signup: true for signup validation, false for login validation  
     - username and password
     - input_verify, input_email: optional parameters
    returns: 
      - returns true if input is valid, false otherwise and
      - dictionary (params) of errors
    """

    params = {}
    valid_input = True

    valid_username = utils.valid_username(input_username)
    if not valid_username:
        valid_input = False
        params['error_username'] = "Invalid username"

    valid_password = utils.valid_password(input_password)
    if not valid_password:
        valid_input = False
        params['error_password'] = "Invalid password"

    if not input_verify and signup:
        valid_input = False
        params['error_verify'] = "verify password"        

    if input_verify and signup:
        valid_verify = utils.valid_password(input_verify)
        if input_password != input_verify:
            valid_input = False
            params['error_verify'] = "Password and Verification do not match"

    if input_email and signup:
        valid_email = utils.valid_email(input_email)
        if not valid_email:
                params['error_email'] = "Invalid email address"
                params['return_email'] = input_email

    return valid_input, params

def user_exists(username):

    exists = False
    users = db.GqlQuery("SELECT * FROM User")
    for user in users:
        if username == user.username:
            exists = True
    return exists

def compare_usernames(input_username):
    param = {}
    match = False
    username = ""

    users = db.GqlQuery("SELECT * FROM User")
    for user in users:
        if input_username == user.username:
            match = True
            param["existing_username"] = "That user already exists"
    return match, param

def get_users_key(group = 'default'):
    """
    returns key for all users
    """
    return db.Key.from_path('users', group)

def get_pages_key(group = 'default'):
    """
    returns key for all pages
    """
    return db.Key.from_path('pages', group)

app = webapp2.WSGIApplication([ ('/signup', SignupHandler),
                                ('/login', LoginHandler),
                                ('/logout', LogoutHandler),
                                ('/_edit' + PAGE_RE, EditHandler),
                                ('/_history' + PAGE_RE, HistoryHandler),
                                (PAGE_RE, WikiPageHandler)], debug=True)

