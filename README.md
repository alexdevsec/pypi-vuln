

About
=====

For slides about this presentation, head over to [my slides from my March 2019 presentation](https://github.com/alexdevsec/pypi-vuln/blob/master/slides/OWASP%20supply%20chain%2020190321.pdf).

This program helps calculate which packages in the pypi repository have known vulnerabilities.
It uses Pyup's safety to determine it.

This is rough code. 


Installation
============

## Requirements

On the host:
* docker, configured so the current user can run containers
* python3

Install python requirements:
`pip install --user -r requirements.txt`

Build the container image with:
`cd container ; make`

## Google sheets credentials

Create a google sheet and get a service account. Save the token in sheets\_creds.json.

## Set the correct version of python
Different results will be created for different versions of python. Specify this by editing the config section in pypi-vuln.py.


Running
=======
Create a list of packages to verify. Most likely, you'll want to get this list from https://pypistats.org. This 
should be put in a flat file. Call this file list.txt

Run:
python3 pypi-vuln.py list.txt

This should populate the spreadsheet with all relevant information.






