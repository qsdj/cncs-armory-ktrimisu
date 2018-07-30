# import os
# from distutils.core import setup
from setuptools import setup, find_packages

setup(name='CScanPoc',
      version='1.0',
      description='POC dev interface',
      author='CScan',
      url='',
      packages=find_packages(),
      package_data={'': ['*.json']},
      scripts=['scripts/poc_exe.py'])
