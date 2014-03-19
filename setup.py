#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup
import bottleauth

description = "Bootle authentication, for Personal, Google, Twitter and "
"Facebook."

setup(
    name='bottleauth',
    version=bottleauth.__version__,
    description=description,
    author=bottleauth.__author__,
    author_email=bottleauth.__email__,
    url='https://github.com/avelino/bottle-auth',

    package_dir={'bottleauth': 'bottleauth'},

    install_requires=[
        'webob',
        'tornado'
    ],
)
