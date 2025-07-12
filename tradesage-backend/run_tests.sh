#!/bin/bash
# Script to run pytest with PYTHONPATH set to the root directory

export PYTHONPATH=$(pwd)
python -m pytest auth_service/tests/test_auth.py -v -s
