#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps

from bottle import request


def login(auth):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                auth.engine.get_user(request.environ)
                return func(*args, **kwargs)
            except:
                return auth.engine.redirect(request.environ)
        return wrapper
    return decorator
