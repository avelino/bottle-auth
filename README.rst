bottle-auth
===========

Bottle plugin authentication, support with Google, Twitter and Facebook


Example
-------

.. code-block:: python

    from bottle import route, redirect, request
    from bottleauth.social.facebook import Facebook, UserDenied, NegotiationError
    from pprint import pformat

    facebook = Facebook('fb-key', 'fb-secret',
                        'http://127.0.0.1:8080/facebook/callback', 'email')

    @route('/login')
    def login():
        url = facebook.redirect(request.environ)
        redirect(url)

    @route('/callback')
    def callback(provider):
        try:
            user = facebook.get_user(request.environ)
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
5. Fill out the Client ID form for a “web application” and use localhost:8000 as your hostname
