# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup, find_packages

setup(name="csp-validator",
      version="0.3",
      description="Content-Security-Policy validator",
      author="Yeuk Hon Wong",
      classifiers=[
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: Security',
      ],
      author_email="yeukhon@acm.org",
      packages=find_packages(),
)
