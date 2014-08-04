#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps

from bottle import request


def login():
    def decorator(func):
        @wraps(func)
        def wrapper(auth, *args, **kwargs):
            try:
                auth.get_user(request.environ)
                return func(*args, **kwargs)
            except:
                return auth.redirect(request.environ)
        return wrapper
    return decorator
