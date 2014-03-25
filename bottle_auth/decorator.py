#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps
from bottle import redirect, request
from bottle.ext import auth
from bottle.ext.core.exception import UserDenied


def login(url='/login'):
    def wrapper(func):
        @wraps(func)
        def check(*args, **kwargs):
            try:
                auth.get_user(request.environ)
            except UserDenied:
                redirect(url)
            return func(*args, **kwargs)
        return check
    return wrapper
