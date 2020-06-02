from pathlib import Path

from setuptools import setup

# using the same libraries in requirements.txt because after many articles I didn't understand any good reason why I shouldn't
requirements = ""
p = Path("requirements.txt")
if p.exists():
    requirements = p.read_text()

# load long description
p = Path("README.md")
if p.exists():
    long_description = p.read_text()

setup(
    name='convey',
    version="1.3.8",
    packages=['convey'],
    author='Edvard Rejthar',
    author_email='edvard.rejthar@nic.cz',
    url='https://github.com/CZ-NIC/convey',
    license='GNU GPLv3',
    description='CSV processing and mutual conversion of web related data types',
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=[requirements.split("\n")],
    entry_points={
        'console_scripts': [
            'convey = convey.__main__:main',
        ],
    },
    include_package_data=True
)
