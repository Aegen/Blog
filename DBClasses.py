from google.appengine.ext import ndb

class Users(ndb.Model):

    username   = ndb.StringProperty(required = True)
    hashedPass = ndb.StringProperty(required = True)
    salt       = ndb.StringProperty(required = True)
    email      = ndb.StringProperty()
    created    = ndb.DateTimeProperty(auto_now_add = True)



class Store(ndb.Model):

    title      = ndb.StringProperty(required = True)
    content    = ndb.TextProperty(required = True)
    created    = ndb.DateTimeProperty(auto_now_add = True)
    creator    = ndb.StringProperty()
    ip_address = ndb.StringProperty()



class CommentStorage(ndb.Model):
	
    username = ndb.StringProperty(required = True)
    permakey = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    content = ndb.TextProperty(required = True)
    ip_address = ndb.StringProperty()