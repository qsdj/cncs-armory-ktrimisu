# coding: utf-8

import argparse


def create_poc_cmd_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "-u", "--url", dest="url", required=True,
        help="目标 URL (e.g. \"http://www.shit.com/\")")
    parser.add_argument(
        '--log-level', required=False, default='DEBUG',
        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS', 'REPORT'],
        help="日志级别, default: DEBUG")
    parser.add_argument(
        '--mode', required=False, default="verify", choices=["verify", "exploit"],
        help="POC 执行模式, default: verify")

    # 执行参数解析
    parser.add_argument('--exec-option', metavar='KEY=VALUE', type=str, nargs='+',
                        help='执行参数定义')
    return parser
