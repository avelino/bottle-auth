bottle-auth
===========

Bottle plugin authentication, support with Google, Twitter and Facebook


Example
-------

.. code-block:: python

    from bottle import route, redirect, request
    from bottle.ext import auth
    from bottleauth.social.facebook import Facebook, UserDenied, NegotiationError
    from pprint import pformat

    facebook = Facebook('fb-key', 'fb-secret',
                        'http://127.0.0.1:8000/callback', 'email')

    app = bottle.Bottle()
    plugin = auth.Plugin(facebook)
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


Google
------

Create project
++++++++++++++

1. Sign into your Google Apps account in your browser
2. Visit `https://code.google.com/apis/console#access <https://code.google.com/apis/console#access>`_ in the same browser
3. On the left menu, Create a new Project
4. To start, you don’t need any Services, so select the API Access tab rom the left menu and “Create an OAuth 2.0 client ID…”
5. Fill out the Client ID form for a **web application** and use *localhost:8000* as your hostname
