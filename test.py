from bottle import Bottle, redirect, request, run
from bottle.ext import auth
from bottle.ext.auth.social.facebook import Facebook, UserDenied
from bottle.ext.auth.social.facebook import NegotiationError
from pprint import pformat

facebook = Facebook('fb-key', 'fb-secret',
                    'http://127.0.0.1:8000/callback', 'email')

app = Bottle()
plugin = auth.AuthPlugin(facebook)
app.install(plugin)


@app.route('/login')
def login(auth):
    url = auth.redirect(request.environ)
    redirect(url)


@app.route('/callback')
def callback(provider):
    try:
        user = auth.get_user(request.environ)
    except UserDenied:
        return 'User denied'
    except NegotiationError:
        return 'Negotiation error, maybe expired stuff'

    return '<pre>{}</pre>'.format(pformat(user))


run(app=app, host='0.0.0.0', port='3333', debug=True)
