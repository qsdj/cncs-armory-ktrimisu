#!/usr/bin/env python3
# coding: utf-8

'''策略执行'''

import sys

from CScanPoc.lib.api.common import create_cmd_parser
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger
from CScanPoc.lib.core.log import setup_cscan_poc_logger
from CScanPoc.lib.utils.indexing import find_strategy


def create_parser():
    '''创建命令行解析'''
    parser = create_cmd_parser()
    parser.add_argument('--strategy-id', dest='strategy_id', help='要执行的策略')
    parser.add_argument('--component', dest='component', help='组件名')
    return parser


def main():
    '''策略执行入口'''
    args = None
    parser = create_parser()
    try:
        args = parser.parse_args()
    except:
        return

    if not args.strategy_id:
        parser.print_usage()
        sys.exit(1)

    setup_cscan_poc_logger(verbose=args.verbose,
                           very_verbose=args.very_verbose)
    (strategy_id, index_dir) = (args.strategy_id, args.index_dir)

    strategy = None
    try:
        logger.debug('查找 Strategy[id=%s] index_dir=%s', strategy_id, index_dir)
        strategy = find_strategy(strategy_id, index_dir)
    except:
        logger.exception('Strategy[id=%s, index_dir=%s]加载失败，退出执行',
                         strategy_id, index_dir)
        raise

    try:
        if args.component:
            strategy.component_name = args.component
        strategy.run(args=args)
    except:
        logger.exception('%s执行异常', strategy)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
