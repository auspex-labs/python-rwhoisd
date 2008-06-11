#!/usr/bin/env python

from distutils.core import setup
import os

setup(name="python-rwhoisd",
      version="0.4",
      description="A lightweight RWhois server written in Python",
      author="David Blacka",
      author_email="david@blacka.com",
      url="http://blacka.com/software/python-rwhoisd",
      packages=['rwhoisd'],
      scripts=['bin/'+x for x in os.listdir('bin')
               if os.path.isfile('bin/'+x)],
      data_files=[('lib/pyrwhoisd/sample_data',
                   ['sample_data/example_schema',
                    'sample_data/example_data'])]
     )
