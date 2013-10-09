#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import urllib
import urllib2
import re
import jinja2
import webapp2
import string
import json
import datetime
import StaticLib as Stat

from google.appengine.api import memcache
from google.appengine.ext import ndb




JINJA_ENVIRONMENT = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), 
        extensions=['jinja2.ext.autoescape']
    )


class MainHandler(webapp2.RequestHandler):

    def get(self):
        temp = memcache.get('maincache')

        userorlogin = None
        usercookie =  self.request.cookies.get('user')
        
        if usercookie:
            usercookie = Stat.eschtml(usercookie)
            userorlogin = '<b><span id = "username">%s[<a style = "color: gray;" href = "/logout">Logout</a>]</span></b>' % usercookie
        else:
            userorlogin = '<b><a style = "color: #565051;" id = "username" href = "/login">Login</a></b>'

        entries =[]
        intime = None
        if temp is not None:

            intime = memcache.get('maintime')
            a = json.loads(temp)

            for b in a:
                temporary = Store()
                temporary.content = b["content"]
                temporary.title = b["title"]
                temporary.created = datetime.datetime.strptime(b["created"], "%Y-%m-%d %H:%M:%S.%f")
                entries.append(temporary)
        else:

            entries = Store.query().order(-Store.created)
            outp = []

            for a in entries:
                inp = {}
                inp["content"] = a.content
                inp["title"] = a.title
                inp["created"] = str(a.created)
                outp.append(inp)

            memcache.set('maincache', json.dumps(outp))
            memcache.set('maintime', datetime.datetime.now())

            intime = datetime.datetime.now()
        
        timedif = (datetime.datetime.now() - intime).total_seconds()
        timescale = 'seconds'
        if timedif >= 60 and  timescale == 'seconds':
            timedif = timedif / 60
            timescale = 'minutes'
        if timedif >= 60 and timescale == 'minutes':
            timedif = timedif / 60
            timescale = 'hours'
        if timedif >= 24 and timescale == 'hours':
            timedif = timedif / 24
            timescale = 'days'

        template = JINJA_ENVIRONMENT.get_template('layout.html')
        self.response.write(template.render( {'entries': entries, 'timedif': timedif, 'timescale':timescale, 'userorlogin': userorlogin}))

    def post(self):
        self.redirect('/')
    	




class MainJsonHandler(webapp2.RequestHandler):

    def get(self):
        entries = Store.query().order(-Store.created)
        outp = []
        for a in entries:
            inp = {}
            inp["content"] = a.content
            inp["title"] = a.title
            inp["created"] = str(a.created)
            outp.append(inp)

        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(outp))




class NewPostHandler(webapp2.RequestHandler):
    
    def get(self):

        self.response.write(JINJA_ENVIRONMENT.get_template('newpostpage.html').render())

    def post(self):

        tit = self.request.get('subject')
        cont = self.request.get('content')

        if tit and cont:
    
            temp = Store(title = Stat.eschtml(tit), content = Stat.eschtml(cont), ip_address = self.request.remote_addr)
            if self.request.cookies.get('user'):
                temp.creator = Stat.eschtml(self.request.cookies.get('user'))

            temp.put()
            memcache.delete('maintime')
            memcache.delete('maincache')

            self.redirect("/" +str(temp.key.id()))
        else:
            self.response.write(JINJA_ENVIRONMENT.get_template('newpostpage.html').render())





class Permalink(webapp2.RequestHandler):
    
    def get(self):
        path = int(self.request.path[1:len(self.request.path)])

        temp = memcache.get(str(path) + "cache")

        s = None
        outer = datetime.datetime.now()


        if temp is not None:
            outer = memcache.get(str(path) + "time")
            a = json.loads(temp)

            s = Store()
            s.content = a["content"]
            s.title = a["title"]
            s.created = datetime.datetime.strptime(a["created"], "%Y-%m-%d %H:%M:%S.%f")
        else:
            s = Store.get_by_id(path)
            if s:
                tempo = {}
                tempo["title"] = s.title
                tempo["content"] = s.content
                tempo["created"] = str(s.created)
                memcache.set(str(path) + "cache", json.dumps(tempo))
                memcache.set(str(path) + "time", datetime.datetime.now())
                outer = datetime.datetime.now()

        timedif = (datetime.datetime.now() - outer).total_seconds()


        if s:
            self.response.write(JINJA_ENVIRONMENT.get_template('permalink.html').render({'hord': s, 'timedif': timedif}))

    def post(self):
        pass 




class PermaJson(webapp2.RequestHandler):

    def get(self):
        outer = self.request.path[1:len(self.request.path)].split('.')[0]

        s = Store.get_by_id(int(outer))
        inp = {}
        inp["content"] = s.content
        inp["title"] = s.title
        inp["created"] = str(s.created)

        self.response.headers['Content-Type'] = 'application/json'

        self.response.write(json.dumps(inp))



class SignupHandler(webapp2.RequestHandler):

    def get(self):
        
        self.response.write(JINJA_ENVIRONMENT.get_template('signup.html').render({'uerr':'', 'perr':'', 'vperr':'', 'emerr':''}))

    def post(self):

        redirect = True
        uerr = ''
        perr = ''
        vperr = ''
        emerr = ''

        u = self.request.get('username')
        p = self.request.get('password')
        vp = self.request.get('verify')
        em = self.request.get('email')

        uRe = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        pRe = re.compile(r"^.{3,20}$")
        eRe = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

        if not uRe.match(u):
            uerr = 'username not valid'
            redirect = False

        if not pRe.match(p):
            perr = 'password not valid'
            redirect = False

        if not p == vp:
            vperr = "passwords don't match"
            redirect = False

        if em:
            if not eRe.match(em):
                emerr = 'email not valid'
                redirect = False

        if not redirect:
            self.response.write(JINJA_ENVIRONMENT.get_template('signup.html').render({'uerr':uerr, 'perr':perr, 'vperr':vperr, 'emerr':emerr}))
        else:
            
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % Stat.eschtml(str(u)))
            tempCode = Stat.salt()
            self.response.headers.add_header('Set-Cookie', 'session_code = %s; Path=/' % tempCode)
            memcache.set(str(u) + '_session_code', tempCode)

            outs = Stat.hashpass(Stat.eschtml(str(u)), Stat.eschtml(str(p))).split(",")
            
            temp = Users()
            temp.username = Stat.eschtml(str(u))
            temp.hashedPass = outs[0]
            temp.salt = outs[1]
            if em:
                temp.email = Stat.eschtml(em)
            temp.put()
            
            self.redirect('/')





class LoginHandler(webapp2.RequestHandler):

    def get(self):

        self.response.write(JINJA_ENVIRONMENT.get_template('login.html').render())

    def post(self):

        user = self.request.get('username')
        passw = self.request.get('password')

        outp = Users.query(Users.username == str(user)).get()

        
        if outp and Stat.hashpass(str(user), str(passw), outp.salt).split(",")[0] == outp.hashedPass and outp.username == user:
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % Stat.eschtml(str(user)))
            tempCode = Stat.salt()
            self.response.headers.add_header('Set-Cookie', 'session_code = %s; Path=/' % tempCode)
            memcache.set(str(user) + "_session_code", tempCode)
            self.redirect('/')
        else:
            self.response.write(JINJA_ENVIRONMENT.get_template('login.html').render())



class LogoutHandler(webapp2.RequestHandler):

    def get(self):
        username = self.request.cookies.get('user')
        self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % '')
        self.response.headers.add_header('Set-Cookie', 'session_code = %s; Path = /' % '')
        memcache.delete(username + '_session_code')
        self.redirect('/')



class Users(ndb.Model):

    username = ndb.StringProperty(required = True)
    hashedPass = ndb.StringProperty(required = True)
    salt = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add = True)



class Store(ndb.Model):

    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    creator = ndb.StringProperty()
    ip_address = ndb.StringProperty()



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPostHandler),
    ('/[0-9]+', Permalink),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/.json', MainJsonHandler),
    ('/[0-9]+\.json', PermaJson)
], debug=True)
