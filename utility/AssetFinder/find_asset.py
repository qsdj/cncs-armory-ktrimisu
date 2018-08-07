#!/usr/bin/env python
# coding: utf-8
import argparse
import json
import logging
import os
import re
import sys
import tempfile

MASSCAN_CMD = '{masscan_bin} {host} -p {ports} --rate {rate} -oL {outfile}'

COMMON_PORTS = [21, 22, 23, 25, 53, 69, 80, 110, 443, 1080, 1158,
                1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001,
                8000, 8080, 8081, 9080, 9090]


def run_masscan(host, outfile, rate, masscan_bin, ports=COMMON_PORTS):
    if isinstance(ports, (set, list, tuple)):
        ports = ','.join([str(x) for x in ports])
    cmd = MASSCAN_CMD.format(masscan_bin=masscan_bin,
                             host=host,
                             ports=ports,
                             rate=rate,
                             outfile=outfile)
    logging.info('执行: %s', cmd)
    os.system(cmd)


def parse_result(outfile):
    ippattern = re.compile(
        r'((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))')
    iplist = []
    with open(outfile) as outf:
        iplist = ippattern.findall(str(outf.readlines()))
    return iplist


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
    parser.add_argument(
        '--masscan-bin', required=False, dest='masscan_bin',
        help='masscan 二进制文件')
    parser.add_argument('-r', dest='rate', type=int,
                        help='(masscan)请设置扫描并发率 (并发率越高扫描的精度越低,默认1000)')
    return parser


def print_result(result, json_out_file=None):
    '''打印最终结果'''
    if json_out_file is not None:
        with open(json_out_file, 'w') as out:
            json.dump(result, out)
    else:
        print('RESULT_START')
        print(json.dumps(result))
        print('RESULT_END')


def main(masscan_bin='masscan/masscan'):
    parser = create_cmd_parser()
    args = parser.parse_args()
    masscan_bin = args.masscan_bin or masscan_bin
    setup_logger()
    _, outfile = tempfile.mkstemp()
    rate = args.rate or 1000
    run_masscan(args.url, outfile, rate, masscan_bin)
    result = parse_result(outfile)
    print_result(result, args.json_out_file)


if __name__ == '__main__':
    main()
