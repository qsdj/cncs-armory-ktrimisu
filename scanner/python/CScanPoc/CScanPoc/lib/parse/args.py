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
    # 组件属性定义
    parser.add_argument('--component-property', metavar='COMPONENT.PROPERTY=VALUES',
                        type=str, nargs='+',
                        dest='component_properties',
                        help='组件属性定义')
    return parser


def parse_args(self, args):
    # self.target = args.url
    for opt in args.exec_option or []:
        (k, v) = (opt, True)
        if '=' in opt:
            (k, v) = opt.split('=', 1)
        self.set_option(k, v)

    for opt in args.component_properties or []:
        (k, v) = (opt, True)
        if '=' in opt:
            (k, v) = opt.split('=', 1)

        (component_name, prop) = (self.vuln.product, k)
        if '.' in k:
            (component_name, prop) = k.split('.', 1)

        self.set_component_property(component_name, prop, v)
