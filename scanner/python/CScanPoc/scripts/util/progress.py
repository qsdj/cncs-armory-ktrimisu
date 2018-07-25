import sys


def progress(count, total, prefix='', sufix=''):
    sys.stdout.write("\033[K")
    sys.stdout.write('%s [%s/%s] %s\r' % (prefix, count, total, sufix))
    sys.stdout.flush()
