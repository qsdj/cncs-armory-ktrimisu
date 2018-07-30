# coding: utf-8

import logging
import argparse
import mysql.connector
from CScanPoc.lib.utils.sort_pocs import sort_pocs
from CScanPoc.lib.utils.cscan_db import CScanDb
from CScanPoc.lib.utils.indexing import indexing


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--sort', dest='sort',
                        action='store_true', help='整理 POC 将所有 POC 放置到 产品类型/产品名 目录中')
    # 数据库选项
    parser.add_argument('--host', dest="host", help="数据库地址")
    parser.add_argument("--user", dest="user", help="数据库用户")
    parser.add_argument('--db', dest="db", help="数据库名")
    parser.add_argument('--port', dest='port', help='数据库端口')
    parser.add_argument('--pass', dest="passwd", help="数据库密码")

    parser.add_argument('--skip-syncing', dest='skip_syncing',
                        action='store_true', help='跳过同步')
    parser.add_argument('--poc-dir', dest='poc_dir', required=True,
                        help='目标目录，将递归处理目录下所有 .py 结尾文件')
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-vv', dest='very_verbose', action='store_true',
                        help='very verbose')

    parser.add_argument('--skip-indexing', dest='skip_indexing',
                        action='store_true', help='跳过索引创建')
    parser.add_argument('--index-dir', dest='index_dir',
                        help='索引信息存放目录，默认当前目录 index 目录下')
    parser.add_argument('--update', dest='update',
                        action='store_true', help='如果数据存在，执行更新操作')

    parser.set_defaults(verbose=False, very_verbose=False, indexing=True,
                        update=False, skip_indexing=False, skip_syncing=False,
                        host='localhost', user='root', db='cscan', passwd='', port=3306)

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

    if args.sort:
        sort_pocs(args.poc_dir)
        return

    if not args.skip_indexing:
        logging.info('Indexing...')
        indexing(args.poc_dir)

    if not args.skip_syncing:
        logging.info('Syncing...')
        cnx = mysql.connector.connect(
            user=args.user,
            password=args.passwd,
            host=args.host,
            database=args.db,
            port=args.port,
            charset='utf8')
        CScanDb(cnx,
                args.index_dir,
                args.update,
                args.update,
                args.update).sync_poc()


if __name__ == '__main__':
    try:
        main()
    except:
        logging.exception('执行出错')
