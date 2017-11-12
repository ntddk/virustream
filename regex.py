#!/usr/bin/env python
#coding: utf-8

import re

md5_pattern = re.compile(r'([a-f0-9]{32}|[A-F0-9]{32})')
sha1_pattern = re.compile(r'([a-f0-9]{40}|[A-F0-9]{40})')
sha256_pattern = re.compile(r'([a-f0-9]{64}|[A-F0-9]{64})')

