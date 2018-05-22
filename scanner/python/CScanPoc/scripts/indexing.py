# coding: utf-8

import os
import sys
import json
import importlib

if __name__ == '__main__':
    m = {}
    if (len(sys.argv) < 3):
        print '<poc目录> <poc_id -> POC_MODULE 输出文件>'
        sys.exit(1)
    for name in os.listdir(sys.argv[1]):
        if name.endswith('.py'):
            name = name[:-3]
        else:
            continue
        try:
            poc = getattr(importlib.import_module('CScanPoc.pocs.' + name),
                          'Poc')()
            if not poc.poc_id or poc.poc_id.strip() == '':
                print '{0} poc_id 未指定'.format(name)
            else:
                m[poc.poc_id] = 'CScanPoc.pocs.{0}'.format(name)
        except Exception as e:
            print e
            print '{0} 未找到 Poc'.format(name)

    out = sys.argv[2]
    if out == '-':
        print json.dumps(m, indent=2, sort_keys=True)
    else:
        with open(out, 'w') as outfile:
            json.dump(m, outfile)
