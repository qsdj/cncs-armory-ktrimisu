#!/usr/bin/env python3
# coding: utf-8

'''任务推荐'''

import json
from CScanPoc.lib.core.log import get_scan_outputer, setup_cscan_poc_logger
from CScanPoc.lib.api.common import create_cmd_parser, parse_properties
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger


def recommend(components_properties):
    '''返回推荐执行策略任务

    针对特定资产进行推荐

    :param components_properties: 组件属性
        {
          [component_name: string]: {
            [prop_name: string]: 'string' | 'number' | 'boolean'
          }
        }
    '''
    # components_properties: 资产当前所有组件及其属性

    outputer = get_scan_outputer()
    components = set(components_properties.keys())

    http_components = ['Apache', 'Nginx', 'IIS', 'uWSGI', 'Tomcat', 'Node.js']

    if not any([c in components for c in http_components]) and (
            'http' in components or 'https' in components):
        # 如果指定的一组 http 组件都未被发现且存在 http/https 服务，扫描所有这些组件
        for c in http_components:
            components.add(c)

    for component in components:
        if component in ('http', 'https'):
            continue
        outputer.report(json.dumps({
            'type': 'strategy',
            'strategy_id': 'simple-component-scan-strategy',
            'exec_option': ['component=\'%s\'' % component]
        }))


def main():
    args = None
    parser = create_cmd_parser()
    try:
        args = parser.parse_args()
    except:
        logger.exception('解析错误')
        raise
    setup_cscan_poc_logger(verbose=args.verbose,
                           very_verbose=args.very_verbose)

    logger.debug('解析组件属性')
    components_properties = {}
    parse_properties(args, components_properties=components_properties)

    logger.info('开始尝试推荐任务')
    recommend(components_properties)


if __name__ == '__main__':
    main()
