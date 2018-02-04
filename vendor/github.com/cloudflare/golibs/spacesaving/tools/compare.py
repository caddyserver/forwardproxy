#!/usr/bin/env python

import sys
import string

maxlines = int(sys.argv[3] or '1000', 10)

perfect = {}

with open(sys.argv[1], 'r') as f:
    for line in map(string.strip, f):
        key, v0 = line.split(",", 1)
        perfect[key] = float(v0)

count = 0
low = 0.0
up = 0.0

perfect_max = max(perfect.itervalues())

print "%50s\t%s\t\t%s\t\t%s\t\t%s" % (
    "key", "min", "max", "real", "error"
    )

with open(sys.argv[2], 'r') as f:
    for line in map(string.strip, f):
        key, v1, v2 = line.split(",", 2)
        v1, v2 = float(v1), float(v2)

        vp = perfect[key]
        del perfect[key]
        if v1 <= vp <= v2:
            err = False
        else:
            err = True
            #print "%s: %f %f %f" % (key, v1, vp, v2)

        count += 1
        low += (vp-v1)**2
        up += (v2-vp)**2

        if count < maxlines or err:
            print "%50s\t%f\t%f\t%f\t%f%s" % (
                key[:50], v1, v2, vp, (vp-v1)**2 + (v2-vp)**2, "\tERROR" if err else "")

print
k, v = max(perfect.iteritems(), key=lambda (k,v): v)
print "Item with max rate uncaptured:"
print "%50s\t\t\t\t\t%f" % ('> ' + k[:48], v)
print
print "%50s\t%f\t%f\t\t\t%f" % (
    "mean error per item (%i items):" % count, low/count, up/count, (low+up)/count
)
print "%50s\t\t\t\t\t%f" % (
    "total uncounted rate (%i items):" % len(perfect), sum(perfect.itervalues())
)
