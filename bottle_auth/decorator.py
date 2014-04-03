#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps

from bottle import redirect, request
from bottle.ext import auth


def login(url='/login'):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                auth.get_user(request.environ)
                return func(*args, **kwargs)
            except:
                return redirect(url)
        return wrapper
    return decorator
