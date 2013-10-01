import cgi
import string
import random
import hashlib
import memcache

#@staticmethod
def eschtml( s):

    return cgi.escape(s)

#@staticmethod
def salt():

    return ''.join(random.choice(string.letters + string.digits) for x in xrange(16))

#@staticmethod
def hashpass( user, passw, sal = None):

    if sal == None:
        sal = salt()

    has = hashlib.sha256(str(user) + str(passw) + str(sal)).hexdigest()
        
    return str(has) + "," + sal


def isLoggedIn(username):
    if memcache.get(username + '_session_code'):
        return True
    else:
        return False