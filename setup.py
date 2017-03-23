#!/usr/bin/python -tt
from setuptools import find_packages, setup

exec(compile(open("openidc_client/release.py").read(),
             "openidc_client/release.py", 'exec'))

setup(
    name='openidc-client',
    version=VERSION,
    description='OpenID Connect Client with caching and token management',
    author='Patrick Uiterwijk',
    author_email='puiterwijk@fedoraproject.org',
    license='MIT',
    keywords='OpenID Connect Client',
    url='https://github.com/puiterwijk/python-openidc-client',
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    install_requires=[
        'requests',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    test_suite='tests',
)
