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
This component provides routing function for the application
"""

from __future__ import print_function

from pox.core import core
from lib import OneWayPath
from bucket import bucket

class DFS(object):
    
    @classmethod
    def findAllPairsPath(cls, matrix):
        path = {}
        def findOneSourcePath(now, origin, way = []):
            for i in matrix[now]:
                if i in way or i == origin:
                    continue
                else:
                    if i not in path[origin]:
                        path[origin][i] = [OneWayPath(way + [i], origin)]
                    else:
                        path[origin][i].append(OneWayPath(way + [i], origin))
                    findOneSourcePath(i, origin, way + [i])

        for i in matrix:
            path[i] = {}
            findOneSourcePath(i, i)
        return path

    @classmethod
    def getPath(cls, src, dst):
        temp_metric = None
        temp_path = []
        for i in bucket.path_list[src][dst]:
            metric_i = i.get_metric()
            if temp_metric == None:
                temp_metric = metric_i
                temp_path = i.path
            elif temp_metric > metric_i:
                temp_metric = metric_i
                temp_path = i.path
        print(temp_path)
        return temp_path

class Djisktra(object):
    
    @classmethod
    def findPath(cls, matrix, source, destination):
        pass
