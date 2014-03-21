#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from pip.req import parse_requirements

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')
requirements = [str(ir.req) for ir in parse_requirements('requirements.txt')]

setup(
    name='python-keybase-client',
    version='0.1.0',
    description='Python client for interacting with the Keybase.io API',
    long_description=readme + '\n\n' + history,
    author='Adam Doyle',
    author_email='adamldoyle@gmail.com',
    url='https://github.com/adamldoyle/python-keybase-client',
    packages=[
        'keybaseclient',
    ],
    package_dir={'keybaseclient': 'keybaseclient'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='python-keybase-client',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ],
    test_suite='tests',
)