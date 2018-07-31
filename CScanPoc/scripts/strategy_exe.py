#!/usr/bin/env python3
# coding: utf-8

'''策略执行'''

import sys
from CScanPoc.lib.utils.indexing import find_poc
from CScanPoc.lib.api.common import create_cmd_parser


def create_parser():
    '''创建命令行解析'''
    parser = create_cmd_parser()
    parser.add_argument('--strategy-id', dest='strategy_id', required=True,
                        help='要执行的策略')
    return parser


def main():
    '''策略执行入口'''
    args = create_parser().parse_args()
