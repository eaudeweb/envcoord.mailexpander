#!/bin/sh

rm -rf bin/ lib/ lib64/ local/ include/ build/ dist/ htmlcov/

VENV=virtualenv-15.2.0/virtualenv.py
URL="https://files.pythonhosted.org/packages/b1/72/2d70c5a1de409ceb3a27ff2ec007ecdd5cc52239e7c74990e32af57affe9/virtualenv-15.2.0.tar.gz"

curl $URL > /tmp/virtualenv.tgz
tar xzf /tmp/virtualenv.tgz -C ./
/usr/bin/python2.7 $VENV --clear --system-site-packages ./

bin/pip install -e .
bin/pip install envcoord.mailexpander[testing]

rm -rf ./virtualenv*
