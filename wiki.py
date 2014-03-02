import os
import re
import random
import hashlib
import hmac
import json
from string import letters

import webapp2
import jinja2
import time

import inspect

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'wikitemplates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'INSERT SECRET KEY KERE - JUST A RANDOM STRING OF CHARS'
DEBUG=True

#def render_str(template, **params):
#    t = jinja_env.get_template(template)
#    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('uid', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'uid=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('uid')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

    @classmethod
    def mph(cls, name, pw, salt=None):
        return make_pwd_hash(name, pw, salt)


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def page_key(dbs, name = 'default'):
    return db.Key.from_path(dbs, name)

class Page(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty()
    page_pw_hash = db.StringProperty(required = False)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'name': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'author': self.author}
        return d
    @staticmethod    
    def get_key(path):
        return db.Key.from_path('Name', path)
        
    @classmethod
    def by_path(cls, path):
        q = cls.all()
        q.filter('name = ', get_key(path))
        q.order("-created")
        return q
        
    @classmethod
    def by_id(cls, page_id, path):
        return cls.get_by_id(page_id, cls.get_key(path))

CACHE_KEY = 'top'
#CACHE_TIME_KEY = '0'

def front_page(update = False):
    post = memcache.get(CACHE_KEY)
    if post is None or update:
        post = greetings = Post.all().order('-created')
        memcache.set(CACHE_KEY, post)
#        memcache.set(CACHE_TIME_KEY, time.time())
    return post

def perma_page(post_id, update = False):
    post = memcache.get(post_id)
    if post is None or update:
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        ptime = time.time()
        post = p, ptime
        memcache.set(post_id, post)
    return post
    
class FlushCache(WikiHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def valid_content(content):
    for (i, o) in (("<html", "html"),
        ('<body', "body"),
        ("<head", "head"),
        ("<link", "link"),
        ("<title", "title"),
        ("<iframe", "iframe"),
        ("<form", "form"),
        ("<script", "puppies"),
        ("</body", "/body"),
        ("</html", "/html"),
        ("<div", "div"),
        ("</div", "/div")
        ):
        content = content.replace(i, o)
    return content
    
class Signup(WikiHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
    
    def done(self, *a, **kw):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')
            
PREVPAGE=None
PAGEPASSWORD=None
PWDPageShown=None
class Login(WikiHandler):
    def get(self):
        self.render('login-form.html', title = 'Login')

    def post(self):
        
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(PREVPAGE)
        else:
            msg = 'Invalid login. Check username and password and try again.'
            self.render('login-form.html', error = msg)
            
class Logout(WikiHandler):
    def get(self):
        self.logout()
        self.redirect(self.request.referer)

#------------------------------------------------------------------------------
class EditPage(WikiHandler):

    def get(self, path="/"):
        v = self.request.get('v')
        p=None
        newpage=None
        if path[:2] == "/_":
            # can't edit control pages (pages that start with an underscore)
            self.redirect("/")

        if v:
            p = Page.get_by_id(int(v))
        else:
            p = memcache.get(path)
        if p is None:
            content=""
            newpage=True
        else:
            content = p.content
            global PAGEPASSWORD
            PAGEPASSWORD = p.page_pw_hash
        global PREVPAGE
        PREVPAGE = '/_edit'+path
        content = valid_content(content)
        # login check
        if PAGEPASSWORD:
            self.render("pwdprotectedpage.html", title = path, pagename = path)

        if self.user:
            self.render('newpage.html', title = path, pagename = path, content = content, isnewpage = newpage, securepage = PAGEPASSWORD)
        else:
            self.redirect('/login')
            
    def post(self, path="/"):
        newpage=None
        global PAGEPASSWORD
        ppwd = PAGEPASSWORD
        global PWDPageShown

        errormsg=None
        #login check
        if not self.user:
            self.redirect('/login')

        pagepassword = self.request.get('pagepw')
        content = self.request.get('content')
        page_pwd = self.request.get('pagepw')

        if ppwd and not PWDPageShown:
            if ppwd and not pagepassword:
                errormsg = "Password required!"
                self.render("pwdprotectedpage.html", title = path, pagename = path, errormsg = errormsg)

            if ppwd and pagepassword:
                #this page exists and needs to be authenticated
                if not valid_password(pagepassword):
                    errormsg = "Invalid password"
                    self.render("pwdprotectedpage.html", title = path, pagename = path, errormsg = errormsg)
                else:
                    q = get_cache_page(path)
            
                    pageset = False
                    if q and valid_pw(path, pagepassword, q.page_pw_hash):
                        #password is good
                        pageset = True
                    else:
                        errormsg="Password is incorrect (no match)"

                    if errormsg:
                        self.render("pwdprotectedpage.html", title = path, pagename = path, errormsg = errormsg)
                    else:
                        #show normal edit page
                        PWDPageShown=True
                        self.render('newpage.html', title = path, pagename = path, content = q.content, isnewpage = False, securepage = PWDPageShown)
        else:
            #Password page HAS been shown and validated. Treat as normal.
            if page_pwd:
                #page_pwd has been set, this is a new page (not all new pages have a password.)
                newpage=True
                if not valid_password(page_pwd):
                    errormsg = "Password invalid"
                    self.render('newpage.html', title = path, pagename = path, content = content, errormsg = errormsg, isnewpage = newpage)        
                
            if not content:
                errormsg = "No valid content!"
                self.render('newpage.html', title = path, pagename = path, errormsg = errormsg, isnewpage = newpage)
            else:
                content = valid_content(content)

            if page_pwd:
                #valid password and content.
                #hash password then add to database    
                #ppwd = self.mph(path, page_pwd) #name, password, salt, returns salt,hash
                ppwd = make_pw_hash(path, page_pwd)


            # have valid content. Add to database
            p = Page(name = path, content = content, author = self.user.name, page_pw_hash = ppwd)
            p.put()
            
            #test letting password protected pages get cached
            memcache.set(path, p)
            PWDPageShown=False

            self.redirect(path)
 
def get_cache_page(path = "/", update = False):
    p = memcache.get(path)
    if p is None or update:
        p = Page.all().filter('name =', path).order('-created').get()
        memcache.set(path, p)
    return p
 
class WikiPage(WikiHandler):
    def get(self, path = "/"):
        # lookup page in db - if found, render below. if not, go to edit page
        v = self.request.get('v')
        p=None
        if v:
            p = Page.get_by_id(int(v))
        else:
            p = get_cache_page(path)
        
        global PREVPAGE
        PREVPAGE = path
        if p is None:
            #goto editpage
            self.redirect("/_edit" + path)
        else:
            content = p.content.replace('\n', '<br>')
            if path[:2] == "/_":
                qrc = None
            else:
                qrc = self.request.headers['Host'] + path

            if not p.page_pw_hash:
                self.render("front.html", title = path, content = content, qrc = qrc)
            else:
                #page is password protected.
                self.render("pwdprotectedpage.html", title = path, pagename = path)

    def post(self, path="/"):
        #when password protected pages are submitted
        p = self.request.get('pagepw')
        errormsg=None
        if p is None or not valid_password(p):
            errormsg = "Password is incorrect (invalid)"
            self.render("pwdprotectedpage.html", title = path, pagename = path, errormsg = errormsg)
        #password has been entered, check validity

        
        #q = Page.all().filter('name = ', path).order("-created").get()
        q = get_cache_page(path)
        
        pageset = False
        if q and valid_pw(path, p, q.page_pw_hash):
            #password is good
            pageset = True
        else:
            errormsg="Password is incorrect (no match)"

        if errormsg:
            self.render("pwdprotectedpage.html", title = path, pagename = path, errormsg = errormsg)
        else:
            #show normal page
            p = get_cache_page(path)
            content = p.content.replace('\n', '<br>')
            self.render("front.html", title = path, content = content, securepage=True)




        
class RandomPage(WikiHandler):
    def get(self):
        #get random id from db and show page related

        #get random id from db
        q = Page.all().count()
        i = random.randint(1,q)


        q = Page.all(keys_only=True)
        n = q.count()
        all_keys = list(q)
        key = random.choice(all_keys)
        s = Page.gql("WHERE __key__ = KEY('" + str(key) + "')").get()
        self.redirect(s.name)

        


class HistoryPage(WikiHandler):
    def get(self, path="/"):
        # show all entries for this path from the db in ascending order
        
        # get data from db for path
        p = Page.all().filter('name =', path).order('-created').fetch(limit=100)
        #p.parent_key(path)
        self.render("history_page.html", title = path, pdb = p)

class UserListPage(WikiHandler):
    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            u = self.request.get('u')
            if not u:
                # get list of users from the db
                u = User.all().fetch(limit=100)
                self.render("userlist.html", title = "", userlist = u)
            else:
                p = Page.all().filter('author = ', u).order('-created').fetch(limit=1000)
                self.render('user_page_history.html', title = '%s\'s page history'%u, updb = p, uname = u)


#------------------------------------------------------------------------------            
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_user', UserListPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/', WikiPage),
                               ('/_flushcache', FlushCache),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/random', RandomPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=DEBUG)
