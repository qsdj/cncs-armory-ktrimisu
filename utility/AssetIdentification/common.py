# coding: utf-8

import argparse
import json
import logging
import sys

COMMON_PORTS = [21, 22, 23, 25, 53, 69, 80, 110, 443, 1080, 1158,
                1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001,
                8000, 8080, 8081, 9080, 9090]


def setup_logger():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def create_cmd_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-u', '--url', required=False, dest='url',
        help='识别目标主机 URL/IP/域名')
    parser.add_argument(
        '--json-out-file', required=False, dest='json_out_file',
        help='以 JSON 格式输出结果到文件')
    return parser


def print_result(result, json_out_file=None):
    '''打印最终结果'''
    if json_out_file is not None:
        with open(json_out_file, 'w') as out:
            json.dump(result, out)
    else:
        print('RESULT_START')
        try:
            print(json.dumps(result, ensure_ascii=False))
        except:
            print(json.dumps(result))
        print('RESULT_END')
