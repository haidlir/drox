# The MIT License (MIT)

# Copyright (c) 2015 haidlir

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This is the cli component of the application, which provides command line interface
function for the application.
"""

from __future__ import print_function
import time

from bucket import bucket

from pox.core import core

class cli(object):

    def print_path():
        for i in bucket.path_list:
            print('source', i)
            for j in bucket.path_list[i] :
                print('    destination', j)
                for k in bucket.path_list[i][j]:
                    print('        ',k.path, k.get_metric())

    def print_matrix_adj():
        for i in bucket.matrix_adj:
            for j in bucket.matrix_adj[i]:
                print('%s - %s : %s' % (i, j, bucket.matrix_adj[i][j].load))

    def print_port_info():
        for i in bucket.port_info:
            print(i)
            for j in bucket.port_info[i]:
                print(bucket.port_info[i][j])

    def print_arp():
        for i in bucket.arp_table:
            print(i)

    prompt = 'drox> '
    command_dict = {'show path': print_path,\
                    'show matrix': print_matrix_adj,\
                    'show port': print_port_info,\
                    'show arp': print_arp}

    @classmethod
    def main(cls):
        while (True):
            command = raw_input(cls.prompt)
            if command == '':
                pass
            elif command == 'halt':
                core.core.quit()
                break
            elif command in cls.command_dict:
                cls.command_dict[command]()
            else:
                print('command not found')