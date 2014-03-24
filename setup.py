#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup
import bottle_auth

description = "Bootle authentication, for Personal, Google, Twitter and "\
    "facebook."

setup(
    name='bottle-auth',
    version=bottle_auth.__version__,
    description=description,
    author=bottle_auth.__author__,
    author_email=bottle_auth.__email__,
    url='https://github.com/avelino/bottle-auth',

    package_dir={'bottle_auth': 'bottle_auth'},

    install_requires=['webob'],
)
