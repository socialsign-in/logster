###  A sample logster parser file that can be used to count the number
###  of response codes found in an Apache access log.
###
###  For example:
###  sudo ./logster --dry-run --output=ganglia SampleLogster /var/log/httpd/access_log
###
###
###  Copyright 2011, Etsy, Inc.
###
###  This file is part of Logster.
###
###  Logster is free software: you can redistribute it and/or modify
###  it under the terms of the GNU General Public License as published by
###  the Free Software Foundation, either version 3 of the License, or
###  (at your option) any later version.
###
###  Logster is distributed in the hope that it will be useful,
###  but WITHOUT ANY WARRANTY; without even the implied warranty of
###  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
###  GNU General Public License for more details.
###
###  You should have received a copy of the GNU General Public License
###  along with Logster. If not, see <http://www.gnu.org/licenses/>.
###

import time
import re
import datetime
import optparse

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException


nginx_cols=['ip','user','time','req','status','length','referer','ua','access_time']

class NginxLogster(LogsterParser):

    def __init__(self, option_string=None):
        '''Initialize any data structures or variables needed for keeping track
        of the tasty bits we find in the log we are parsing.'''
        self.http_1xx = 0
        self.http_2xx = 0
        self.http_3xx = 0
        self.http_4xx = 0
        self.http_5xx = 0
        self.http_all = 0
        self.http_time_all = 0
        self.slow_reqs = 0

        self.start_time = None
        self.end_time = None
       
        if option_string:
            options = option_string.split(' ')
        else:
            options = []

        optparser = optparse.OptionParser()
        optparser.add_option('--use-logfile-time', '--lt', dest='log_file_time', action='store_true', 
        default=False,help='Use log file parsed times. Default: Use filesystem access time')

        opts, args = optparser.parse_args(args=options)
        self.parse_duration = opts.log_file_time

        # Regular expression for matching lines we are interested in, and capturing
        # fields from the line (in this case, http_status_code).
        self.reg = re.compile('([(\d\.)]+) - (.+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)" (\d+.?\d+)')


    def parse_line(self, line):
        '''This function should digest the contents of one line at a time, updating
        object's state variables. Takes a single argument, the line to be parsed.'''

        try:
            # Apply regular expression to each line and extract interesting bits.
            regMatch = self.reg.match(line)

            if regMatch:
                linebits = regMatch.groups()
                if not self.start_time:
                    self.start_time = linebits[2] 
                self.end_time = linebits[2] 
                status = int(linebits[4])
                access_time_ms = float(linebits[8]) * 1000

                if (status < 200):
                    self.http_1xx += 1
                elif (status < 300):
                    self.http_2xx += 1
                elif (status < 400):
                    self.http_3xx += 1
                elif (status < 500):
                    self.http_4xx += 1
                else:
                    self.http_5xx += 1
                self.http_all += 1
                self.http_time_all += access_time_ms
                if access_time_ms > 700:
                    self.slow_reqs += 1

            else:
                raise LogsterParsingException("regmatch failed to match")

        except Exception as e:
            raise LogsterParsingException("regmatch or contents failed with %s" % e)


    def parse_time_str(self,time_str):
        dt = datetime.datetime.strptime(time_str,'%d/%b/%Y:%H:%M:%S +0000') 
        return dt

    def get_duration(self):
        if not self.start_time or not self.end_time:
            return 0

        if self.start_time == self.end_time:
            return 0

        td = self.parse_time_str(self.end_time)-self.parse_time_str(self.start_time)
        return td.total_seconds()

    def get_state(self, duration):
        '''Run any necessary calculations on the data collected from the logs
        and return a list of metric objects.'''
        ###
        # just override duration if we have times
        ###
        if self.parse_duration:
            duration = self.get_duration()

        ####
        # Assume 1 second if no duration 
        ####
        if not duration:
            duration = 1 

        if not self.http_all:
            return []

        # Return a list of metrics objects
        return [
            #MetricObject("http_1xx", (self.http_1xx / duration), "Responses per sec"),
            #MetricObject("http_2xx", (self.http_2xx / duration), "Responses per sec"),
            #MetricObject("http_3xx", (self.http_3xx / duration), "Responses per sec"),
            #MetricObject("http_4xx", (self.http_4xx / duration), "Responses per sec"),
            MetricObject("http_badreqs",  (self.http_4xx + self.http_5xx)/self.http_all, "% Bad Requests"),
            MetricObject("http_slowreqs",  self.slow_reqs/self.http_all, "% Slow Requests"),
            MetricObject("http_numreqs",  self.http_all, "Http Requests"),
            MetricObject("http_reqs",  self.http_time_all/self.http_all, "Request Time (ms)"),
            #MetricObject("http_2xx", (self.http_2xx / duration), "Responses per sec"),
            #MetricObject("http_3xx", (self.http_3xx / duration), "Responses per sec"),
            #MetricObject("http_4xx", (self.http_4xx / duration), "Responses per sec"),
            #MetricObject("http_5xx", (self.http_5xx / duration), "Responses per sec"),
        ]
