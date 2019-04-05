# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup


with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='osxcollector_output_filters',
    version='1.1.0',
    author='Yelp Security',
    author_email='opensource@yelp.com',
    description='Filters that process and transform the output of OSXCollector',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='GNU General Public License',
    url='https://github.com/Yelp/osxcollector_output_filters',
    setup_requires='setuptools',
    packages=find_packages(exclude=['tests']),
    provides=['osxcollector'],
    install_requires=[
        'threat_intel',
        'tldextract',
        'simplejson',
        'six',
    ],
)
