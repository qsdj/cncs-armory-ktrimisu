# encoding: utf-8

import sys
import logging
import argparse
import mysql.connector
from util.indexing import load_index
from CScanPoc.lib.utils.misc import load_poc_file_as_module, find_vuln_poc


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-vv', dest='very_verbose', action='store_true',
                        help='very verbose')
    parser.add_argument('--index-dir', dest='index_dir', required=False,
                        help='索引信息存放目录，默认当前目录 index 目录下')
    parser.add_argument('--poc-id', dest='poc_id', required=True,
                        help='要执行的 POC 的 ID')

    return parser


def setup_logger(args):
    if args.very_verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)


def main():
    args = create_parser().parse_args()
    setup_logger(args)

    (_, poc_ind, _) = load_index(args.index_dir)
    if args.poc_id not in poc_ind:
        logging.fatal('POC[id={}]不存在，退出执行'.format(args.poc_id))
        sys.exit(1)

    poc_dict = poc_ind[args.poc_id]
    try:
        mod = load_poc_file_as_module(poc_dict.get('path'))
        (_, poc) = find_vuln_poc(mod)
        poc.run()
    except Exception as e:
        logging.fatal('POC[id={}, path={}]加载失败，退出执行'.format(
            args.poc_id, poc_dict.get('path')))
        sys.exit(1)


if __name__ == '__main__':
    main()
