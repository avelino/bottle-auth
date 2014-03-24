#!/usr/bin/env python
# -*- coding: utf-8 -*-


class AuthException(Exception):
    pass


class UserDenied(AuthException):
    pass


class NegotiationError(AuthException):
    pass
