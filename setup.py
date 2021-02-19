from setuptools import setup
from setuptools import find_packages

version = '0.16'

tests_require = ['pytest', 'pytest-cov', 'mock']

setup(
    name='envcoord.mailexpander',
    version=version,
    description="Sendmail mailer with some LDAP checking",
    long_description="""This program acts as a sendmail mailer and allows
    sending mails to a certain ldap group (role).""",
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[],
    keywords='python ldap sendmail',
    author='Eau de Web',
    author_email='office@eaudeweb.ro',
    url='http://www.eaudeweb.ro/',
    license='MPL',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'roleexpander = envcoord.mailexpander.expander:main',
        ]
    },
    install_requires=[],
    tests_require=tests_require,
    extras_require={
        'testing': tests_require,
    }
)
