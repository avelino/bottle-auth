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
