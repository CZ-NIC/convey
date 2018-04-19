from setuptools import setup, find_packages

setup (
       name='konvey',
       version='0.8.0.dev1',
       packages=['lib'],       
       author='Edvard Rejthar',
       author_email='edvard.rejthar@nic.cz',       
       #summary = 'Just another Python package for the cheese shop',
       url='https://github.com/CZ-NIC/convey',
       license='GNU GPLv3',
       description='CSV swiss knife brought by CSIRT.cz. Convenable way to process large files that might freeze your spreadsheet processor.',
       install_requires=['netaddr', "jsonpickle", "ipdb", "pythondialog", "lepl"],

       entry_points = {
              'console_scripts': [
                  'command-name = convey.convey:main',                  
              ],              
          },
       )
