#!/usr/bin/env python3
# coding: utf-8

'''策略执行'''

import json
import sys

from CScanPoc.lib.api.common import create_cmd_parser, parse_properties
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger
from CScanPoc.lib.core.log import get_scan_outputer, setup_cscan_poc_logger
from CScanPoc.lib.utils.indexing import find_strategy


def create_parser():
    '''创建命令行解析'''
    parser = create_cmd_parser()
    parser.add_argument('--strategy-id', dest='strategy_id', help='要执行的策略')
    parser.add_argument('--component', dest='component', help='组件名')
    parser.add_argument('--recommend', dest='recommend', action='store_true',
                        help='推荐策略任务')
    return parser


def components_properties_to_args(components_properties):
    '''组件属性转换成参数列表'''
    args = []
    for component in components_properties:
        properties = components_properties[component]
        for prop in properties:
            val = properties[prop]
            if val is True:
                args.append("%s.%s" % (component, prop))
            else:
                args.append("%s.%s=%s" % (component, prop, val))
    return args


def recommend(args):
    '''返回推荐执行策略任务

    针对特定资产进行推荐

    strategy_exe 参数列表

    :return: {'strategy_id': '',
              'exec_option': [str]}
    '''
    setup_cscan_poc_logger(verbose=args.verbose,
                           very_verbose=args.very_verbose)
    # 组件名:
    #   属性 -> 属性值
    components_properties = {}
    outputer = get_scan_outputer()
    parse_properties(args, components_properties=components_properties)
    # args.url: 目标
    # components_properties: 资产当前所有组件及其属性

    for component in components_properties:
        outputer.report(json.dumps({
            'strategy_id': 'simple-component-scan-strategy',
            'exec_option': ['--component', component]
        }))


def main():
    '''策略执行入口'''
    args = None
    parser = create_parser()
    try:
        args = parser.parse_args()
    except:
        return

    if args.recommend:
        try:
            recommend(args)
        except:
            logger.exception('recommend 出错')
        return

    if not args.strategy_id:
        parser.print_usage()
        print('--strategy_id / --recommend')
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
        logger.exception('%s执行异常', poc)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
