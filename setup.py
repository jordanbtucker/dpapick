#! /usr/bin/env python

from distutils.core import setup

setup(
    name = 'DPAPI',
    version = '0.1',
    packages=['DPAPI'],
    scripts = ['bin/dpapidec'],

    # Metadata
    author = 'Jean-Michel PICOD',
    author_email = 'jmichel.p@gmail.com',
    description = 'DPAPI decryption code',
    license = 'GPLv2',
    # keywords = '',
    # url = '',
)
