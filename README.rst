bottle-auth
===========

Bottle plugin authentication, support with Google, Twitter and Facebook


Example
-------

.. code-block:: python

    from bottle import Bottle, redirect, request, run
    from bottle.ext import auth
    from bottle.ext.auth.decorator import login
    from bottle.ext.auth.social.facebook import Facebook, UserDenied
    from bottle.ext.auth.social.facebook import NegotiationError
    from pprint import pformat

    facebook = Facebook('fb-key', 'fb-secret',
                        'http://127.0.0.1:8000/', 'email')

    app = Bottle()
    plugin = auth.AuthPlugin(facebook)
    app.install(plugin)


    @app.route('/login')
    def login(auth):
        return auth.redirect(request.environ)


    @app.route('/')
    @login(auth)
    def home():
        user = auth.get_user(request.environ)
        return "Home page {}".format(pformat(user))


    run(app=app, host='0.0.0.0', port='3333', debug=True)


Google
------

Create project
++++++++++++++

1. Sign into your Google Apps account in your browser
2. Visit `https://code.google.com/apis/console#access <https://code.google.com/apis/console#access>`_ in the same browser
3. On the left menu, Create a new Project
4. To start, you don’t need any Services, so select the API Access tab rom the left menu and “Create an OAuth 2.0 client ID…”
5. Fill out the Client ID form for a **web application** and use *localhost:8000* as your hostname
