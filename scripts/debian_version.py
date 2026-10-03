"""Debian epoch/upstream/revision ordering (dpkg verrevcmp semantics)."""
import re

def split(version):
    if not re.fullmatch(r'(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*',version):raise ValueError('Invalid Debian version')
    epoch,rest=version.split(':',1) if ':' in version else ('0',version)
    if not epoch.isdigit():raise ValueError('Invalid epoch')
    upstream,revision=rest.rsplit('-',1) if '-' in rest else (rest,'0')
    if not upstream or not revision:raise ValueError('Empty version part')
    return int(epoch),upstream,revision

def part_compare(a,b):
    def order(c):
        if c=='~':return -1
        if not c:return 0
        if c.isdigit():return 0
        return ord(c) if c.isalpha() else ord(c)+256
    i=j=0
    while i<len(a) or j<len(b):
        while (i<len(a) and not a[i].isdigit()) or (j<len(b) and not b[j].isdigit()):
            x=a[i] if i<len(a) else '';y=b[j] if j<len(b) else ''
            if order(x)!=order(y):return (order(x)>order(y))-(order(x)<order(y))
            i+=bool(x);j+=bool(y)
        while i<len(a) and a[i]=='0':i+=1
        while j<len(b) and b[j]=='0':j+=1
        ai=i;bj=j
        while i<len(a) and a[i].isdigit():i+=1
        while j<len(b) and b[j].isdigit():j+=1
        x=a[ai:i];y=b[bj:j]
        if len(x)!=len(y):return (len(x)>len(y))-(len(x)<len(y))
        if x!=y:return (x>y)-(x<y)
    return 0

def compare(a,b):
    x=split(a);y=split(b)
    if x[0]!=y[0]:return (x[0]>y[0])-(x[0]<y[0])
    return part_compare(x[1],y[1]) or part_compare(x[2],y[2])
