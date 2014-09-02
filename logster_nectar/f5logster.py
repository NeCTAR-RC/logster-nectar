# Copyright (c) 2014, Russell Sim
# All rights reserved.
#
# This file is part of Logster-NeCTAR.
#
# Logster-NeCTAR is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Logster-NeCTAR is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Logster-NeCTAR. If not, see
# <http://www.gnu.org/licenses/>.

import re
import socket

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException


def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

regex = '[^\s]+ [^\s]+ (?P<destination_host>[^:]+):' \
        ' .*HTTP/1.\d\" (?P<http_status_code>\d{3}) .*'


class F5Logster(LogsterParser):

    def __init__(self, option_string=None):
        '''Initialize any data structures or variables needed for keeping track
        of the tasty bits we find in the log we are parsing.'''
        self.hosts = {}

        # Regular expression for matching lines we are interested in,
        # and capturing fields from the line (in this case,
        # http_status_code).
        self.reg = re.compile(regex)

    def parse_line(self, line):
        '''This function should digest the contents of one line at a time,
        updating object's state variables. Takes a single argument,
        the line to be parsed.

        '''

        try:
            # Apply regular expression to each line and extract
            # interesting bits.
            regMatch = self.reg.match(line)

            if regMatch:
                linebits = regMatch.groupdict()
                status = int(linebits['http_status_code'])
                host = linebits['destination_host']
                hostname = host.split('.', 1)[0]
                if is_number(hostname):
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                        hostname = hostname.split('.', 1)[0]
                    except:
                        hostname = host.replace('.', '_')

                if hostname not in self.hosts:
                    self.hosts[hostname] = {
                        'http_1xx': 0,
                        'http_2xx': 0,
                        'http_3xx': 0,
                        'http_4xx': 0,
                        'http_5xx': 0,
                    }
                if (status < 200):
                    self.hosts[hostname]['http_1xx'] += 1
                elif (status < 300):
                    self.hosts[hostname]['http_2xx'] += 1
                elif (status < 400):
                    self.hosts[hostname]['http_3xx'] += 1
                elif (status < 500):
                    self.hosts[hostname]['http_4xx'] += 1
                else:
                    self.hosts[hostname]['http_5xx'] += 1

            else:
                raise LogsterParsingException("regmatch failed to match")

        except Exception, e:
            raise LogsterParsingException("regmatch or contents failed with %s" % e)

    def get_state(self, duration):
        '''Run any necessary calculations on the data collected from the logs
        and return a list of metric objects.'''
        self.duration = duration

        # Return a list of metrics objects
        base_metrics = []
        for host, metrics in self.hosts.items():
            for metric, value in metrics.items():
                base_metrics.append(
                    MetricObject("%s.%s" % (host, metric),
                                 (value / self.duration),
                                 "Responses per sec")),

        return base_metrics
