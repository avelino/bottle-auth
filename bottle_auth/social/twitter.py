#!/usr/bin/env python
# -*- coding: utf-8 -*-'
import logging
import re

from bottle import redirect
from bottle_auth.exception import UserDenied, NegotiationError
from bottle_auth.core.auth import TwitterMixin, HTTPRedirect

log = logging.getLogger('bottle-auth.twitter')


class Twitter(object):

    PROFILE_URL_BASE = 'https://twitter.com/'

    def __init__(self, key, secret, callback_url):
        self.settings = {
            'twitter_consumer_key': key,
            'twitter_consumer_secret': secret,
        }
        self.callback_url = callback_url

    def redirect(self, environ, cookie_monster):
        auth = TwitterMixin(environ, self.settings, cookie_monster)

        try:
            auth.authorize_redirect(self.callback_url)
        except HTTPRedirect, e:
            log.debug('Redirecting Twitter user to {0}'.format(e.url))
            return redirect(e.url)
        except KeyError, e:
            log.warning('Negotiation error for Twitter user')
            raise NegotiationError
        return None

    def get_user(self, environ, cookie_monster):
        session = environ.get('beaker.session')
        if session.get("uid", None):
            return session

        auth = TwitterMixin(environ, self.settings, cookie_monster)

        if auth.get_argument('denied', None):
            log.debug('User denied attributes exchange')
            raise UserDenied()

        container = {}

        def get_user_callback(user):
            if not user:
                raise NegotiationError()

            container['uid'] = user['username']
            container['attrs'] = user

            profile_image_small = user['profile_image_url_https']
            profile_image = re.sub('_normal(?=.\w+$)', '', profile_image_small)

            container['parsed'] = {
                'uid': user['id_str'],
                'email': None,
                'username': user['username'],
                'screen_name': user['screen_name'],
                'first_name': user.get('name'),
                'last_name': None,
                'language': user.get('lang'),
                'profile_url': self.PROFILE_URL_BASE + user['username'],
                'profile_image_small': profile_image_small,
                'profile_image': profile_image,
            }
            session.update(container)
            session.save()

        auth.get_authenticated_user(get_user_callback)

        return container
