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
      scripts=os.listdir('bin'),
      data_files=[('sample_data',
                   ['sample_data/example_schema',
                    'sample_data/example_data'])]
     )
