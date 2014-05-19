#!/usr/bin/env python
# -*- coding: utf-8 -*-'
import logging

from bottle import redirect
from bottle_auth.core.exception import UserDenied, NegotiationError
from bottle_auth.core.auth import FacebookGraphMixin, HTTPRedirect


log = logging.getLogger('bottle-auth.facebook')


class Facebook(object):

    PROFILE_IMAGE_URL = 'https://graph.facebook.com/{id}/picture?type=large'
    PROFILE_IMAGE_SMALL_URL = 'https://graph.facebook.com/{id}/picture'

    def __init__(self, key, secret, callback_url, scope='email'):
        self.settings = {
            'facebook_api_key': key,
            'facebook_secret': secret,
        }
        self.callback_url = callback_url
        self.scope = scope

    def redirect(self, environ):
        auth = FacebookGraphMixin(environ)
        try:
            auth.authorize_redirect(
                redirect_uri=self.callback_url,
                client_id=self.settings['facebook_api_key'],
                extra_params={'scope': self.scope})

        except HTTPRedirect, e:
            log.debug('Redirecting Facebook user to {0}'.format(e.url))
            return redirect(e.url)
        return None

    def get_user(self, environ):
        session = environ.get('beaker.session')
        if session.get("uid", None):
            return session

        auth = FacebookGraphMixin(environ)

        if auth.get_argument('error', None):
            log.debug('User denied attributes exchange')
            raise UserDenied()

        container = {}

        def get_user_callback(user):
            if not user:
                raise NegotiationError()

            container['uid'] = user.get('email')
            container['attrs'] = user
            container['parsed'] = {
                'uid': user['id'],
                'email': user.get('email'),
                'username': user.get('username'),
                'screen_name': user.get('name'),
                'first_name': user.get('first_name'),
                'last_name': user.get('last_name'),
                'language': user.get('locale'),
                'profile_url': user.get('link'),
                'profile_image_small': self.PROFILE_IMAGE_SMALL_URL.format(
                    id=user['id']),
                'profile_image': self.PROFILE_IMAGE_URL.format(id=user['id']),
            }
            session.update(container)
            session.save()

        auth.get_authenticated_user(
            redirect_uri=self.callback_url,
            client_id=self.settings['facebook_api_key'],
            client_secret=self.settings['facebook_secret'],
            code=auth.get_argument('code'),
            callback=get_user_callback)

        return container

    def api(self, environ, path, args, access_token):
        auth = FacebookGraphMixin(environ)
        container = {}

        def callback(response):
            container['response'] = response

        auth.facebook_request(path, callback, access_token, args)
        return container.get('response')
