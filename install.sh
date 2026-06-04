#!/bin/sh

rm -rf bin/ lib/ lib64/ local/ include/ build/ dist/ htmlcov/ pyvenv.cfg

# Create the virtualenv in the repo root (stdlib venv, no download needed).
# Do NOT pass --clear with '.' as the target: venv's --clear deletes the
# entire contents of the target directory, which here is the repo root. The
# rm above already removes any previous venv directories.
python3 -m venv .

# python-ldap (an install_requires dependency) builds a C extension, so the
# system needs a compiler and the LDAP/SASL dev headers
# (apt: gcc python3-dev libldap2-dev libsasl2-dev).
bin/pip install -e .[testing]
