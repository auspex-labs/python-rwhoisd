#!/usr/bin/env python

from distutils.core import setup
import os

setup(name="python-rwhoisd",
      version="0.1",
      description="A lightweight RWhois server written in Python",
      author="David Blacka",
      author_email="davidb@verisignlabs.com",
      url="http://www.rwhois.net/",
      packages=['rwhoisd'],
      scripts=['bin/'+x for x in os.listdir('bin')],
      data_files=[('lib/pyrwhoisd/sample_data',
                   ['sample_data/example_schema',
                    'sample_data/example_data'])]
     )
