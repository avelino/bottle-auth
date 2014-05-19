#!/usr/bin/env python
# -*- coding: utf-8 -*-
from bottle import redirect


class Custom(object):
    def __init__(self, login_url="/login",
                 callback_url="http://127.0.0.1:8000",
                 field="username"):
        self.login_url = login_url
        self.callback_url = callback_url
        self.field = field

    def redirect(self, environ):
        return redirect(self.login_url)

    def get_user(self, environ):
        session = environ.get('beaker.session')
        if session.get(self.field):
            return session
        self.redirect(environ)
