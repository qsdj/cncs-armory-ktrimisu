#!/usr/bin/python
# coding: utf-8

import argparse
import json
import logging
import os
import sys
import tempfile
from urlparse import urlparse

WHAT_WEB_CMD = '{what_web_bin} {url} --log-json {output_file}'


def run_whatweb(url, outfile, what_web_bin):
    cmd = WHAT_WEB_CMD.format(
        what_web_bin=what_web_bin, url=url, output_file=outfile)
    logging.info('执行: %s', cmd)
    os.system(cmd)


def setup_logger():
    '''设定日志记录'''
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def create_cmd_parser():
    '''创建命令行解析器'''
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-u', '--url', required=False, dest='url',
        help='识别目标主机 URL/IP/域名')
    parser.add_argument(
        '--json-out-file', required=False, dest='json_out_file',
        help='以 JSON 格式输出结果到文件')
    return parser


class WhatWebResultParser(object):
    '''whatweb 结果解析'''

    def __init__(self, whatweb_outfile):
        with open(whatweb_outfile) as outfile:
            self.whatweb_result = json.load(outfile)
        self.components = {}

    def parse(self):
        for item in self.whatweb_result:
            self._parse_one(item)
        return self.components

    def _parse_one(self, json_obj):
        '''解析某个结果'''
        logging.debug('解析：%s', json_obj)
        if json_obj == {}:
            return
        target = json_obj['target']
        pth = urlparse(target).path
        plugins = json_obj['plugins']
        for name in plugins:
            if name in ('HTTPServer', 'X-Powered-By'):
                self._parse_common(plugins[name])
            elif name == 'MetaGenerator':
                self._parse_meta_generator(plugins[name], pth)

    def _parse_common(self, json_obj):
        '''结果为 组件名/版本 的形式的结果的解析'''
        for item in json_obj.get('string', []):
            item = item.split(' ')[0]
            (name, version) = (item, None)
            if '/' in item:
                name, version = item.split('/', 1)
            info = self.components.get(name, {})
            if version:
                info['version'] = version
            self.components[name] = info

    def _parse_meta_generator(self, json_obj, pth=None):
        '''MetaGenerator 结果的解析'''
        for item in json_obj.get('string', []):
            (name, version) = (item, None)
            if ' ' in item:
                (name, version) = item.split(' ', 1)
            name = item.split(' ')[0]
            info = self.components.get(name, {})
            if version:
                info['version'] = version
            info['deploy_path'] = pth or '/'
            self.components[name] = info


def print_result(result, json_out_file=None):
    '''打印最终结果'''
    if json_out_file is not None:
        with open(json_out_file, 'w') as out:
            json.dump(result, out)
    else:
        print('RESULT_START')
        print(json.dumps(result))
        print('RESULT_END')


def main(what_web_bin='WhatWeb/whatweb'):
    parser = create_cmd_parser()
    args = parser.parse_args()
    setup_logger()
    _, outfile = tempfile.mkstemp()
    run_whatweb(args.url, outfile, what_web_bin)
    result = WhatWebResultParser(outfile).parse()
    print_result(result, args.json_out_file)


if __name__ == '__main__':
    main()
