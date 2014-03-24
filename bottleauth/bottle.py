#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bottle
import inspect


if not hasattr(bottle, 'PluginError'):
    class PluginError(bottle.BottleException):
        pass
    bottle.PluginError = PluginError


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
            elif other.name == self.name:
                self.name += '_%s' % self.keyword

        if self.create and not self.metadata:
            raise bottle.PluginError("Define metadata value to create "
                                     "database.")

    def apply(self, callback, route):
        # hack to support bottle v0.9.x
        if bottle.__version__.startswith('0.9'):
            config = route['config'].get('auth', {})
            _callback = route['callback']
        else:
            config = route.config.get('auth', {})
            _callback = route.callback

        if "auth" in config:
            g = lambda key, default: config.get('auth', {}).get(key, default)
        else:
            g = lambda key, default: config.get('auth.' + key, default)

        keyword = g('keyword', self.keyword)
        argspec = inspect.getargspec(_callback)
        if not (keyword in argspec.args):
            return callback

        def wrapper(*args, **kwargs):
            kwargs[self.keyword] = self.engine
            return callback(*args, **kwargs)

        return wrapper


Plugin = AuthPlugin
