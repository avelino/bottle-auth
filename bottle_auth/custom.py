#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
from bottle import redirect


log = logging.getLogger('bottle-auth.custom')


class Custom(object):
    def __init__(self, login_url="/login",
                 callback_url="http://127.0.0.1:8000"):
        self.login_url = login_url
        self.callback_url = callback_url

    def redirect(self, environ):
        return redirect(self.login_url)

    def get_user(self, environ):
        session = environ.get('beaker.session')
        if session.get("username", None) and session.get("apikey", None):
            return session
        self.redirect(environ)
