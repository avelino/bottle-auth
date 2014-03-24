#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bottle
import AuthPlugin


if not hasattr(bottle, 'PluginError'):
    class PluginError(bottle.BottleException):
        pass
    bottle.PluginError = PluginError


Plugin = AuthPlugin
