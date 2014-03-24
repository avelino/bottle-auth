#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bottle


if not hasattr(bottle, 'PluginError'):
    class PluginError(bottle.BottleException):
        pass
    bottle.PluginError = PluginError


class AuthPlugin(object):
    name = 'auth'

    def __init__(self):
        pass

    def setup(self, app):
        pass

    def apply(self, callback, route):
        pass


Plugin = AuthPlugin
