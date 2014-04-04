#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bottle
import inspect


class AuthPlugin(object):
    name = 'auth'

    def __init__(self, engine, keyword='auth'):
        """
        :param engine: Auth engine created function
        :param keyword: Keyword used to inject auth in a route
        """
        self.engine = engine
        self.keyword = keyword

    def setup(self, app):
        """ Make sure that other installed plugins don't affect the same
            keyword argument and check if metadata is available."""
        for other in app.plugins:
            if not isinstance(other, AuthPlugin):
                continue
            if other.keyword == self.keyword:
                raise bottle.PluginError("Found another auth plugin "
                                         "with conflicting settings ("
                                         "non-unique keyword).")

    def apply(self, callback, context):
        args = inspect.getargspec(context['callback'])[0]

        if self.keyword not in args:
            return callback

        def wrapper(*args, **kwargs):
            kwargs[self.keyword] = self.engine
            return callback(*args, **kwargs)

        return wrapper
