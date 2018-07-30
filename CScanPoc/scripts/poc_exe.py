# encoding: utf-8

import sys
import logging
from CScanPoc.lib.utils.indexing import find_poc
from CScanPoc.lib.parse.args import create_poc_cmd_parser


def create_parser():
    parser = create_poc_cmd_parser()
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
        logging.basicConfig(level=logging.ERROR)


def main():
    args = create_parser().parse_args()
    setup_logger(args)
    (poc_id, index_dir) = (args.poc_id, args.index_dir)

    poc = None
    try:
        poc = find_poc(poc_id, index_dir)
    except:
        logging.exception('POC[id=%s, index_dir=%s]加载失败，退出执行',
                          poc_id, index_dir)
        raise

    try:
        poc.run(args=args)
    except:
        logging.exception('%s执行异常', poc)


if __name__ == '__main__':
    try:
        main()
    except:
        sys.exit(1)
