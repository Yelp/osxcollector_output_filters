# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

setup(
    name="osxcollector_output_filters",
    version="1.0.12",
    author="Yelp Security",
    author_email="opensource@yelp.com",
    description="Filters that process and transform the output of OSXCollector",
    license="GNU General Public License",
    url="https://github.com/Yelp/osxcollector_output_filters",
    setup_requires="setuptools",
    packages=find_packages(exclude=["tests"]),
    provides=["osxcollector"],
    install_requires=[
        "simplejson",
        "threat_intel",
        "tldextract"
    ],
)
