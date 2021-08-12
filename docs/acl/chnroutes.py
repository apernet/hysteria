#! /usr/bin/env python3

import urllib.request
from itertools import chain
from datetime import date

data_ipv4 = urllib.request.urlopen(
    'http://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone')
data_ipv6 = urllib.request.urlopen(
    'http://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone')

data = chain(data_ipv4, data_ipv6)

with open('chnroutes.acl', 'w') as out:
    out.write('# chnroutes\n# Generated on %s\n\n' %
              date.today().strftime("%B %d, %Y"))
    for l in data:
        ls = str(l, 'UTF8').strip()
        if ls:
            out.write('direct cidr %s\n' % ls)
