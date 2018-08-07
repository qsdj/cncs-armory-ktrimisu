#!/usr/bin/python
# coding: utf-8

import argparse
import json
import logging
import os
import re
import sys
import tempfile

NMAP_CMD = '{nmap_bin} -p {ports} -oN {output_file} {hosts}'
COMMON_PORTS = [21, 22, 23, 25, 53, 69, 80, 110, 443, 1080, 1158,
                1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001,
                8000, 8080, 8081, 9080, 9090]


def run_nmap(hosts, outfile, nmap_bin, ports=COMMON_PORTS):
    '''执行 nmap 进行服务扫描'''
    if isinstance(ports, (set, list, tuple)):
        ports = ','.join([str(x) for x in ports])
    cmd = NMAP_CMD.format(
        nmap_bin=nmap_bin, ports=ports, output_file=outfile, hosts=hosts)
    logging.info('执行: %s', cmd)
    os.system(cmd)


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
        '--nmap-bin', required=False, dest='nmap_bin',
        help='NMAP 二进制文件')
    return parser


def parse_nmap_result(nmap_outfile):
    result = {}
    portpattern = re.compile(r'(\d+)/')
    namepattern = re.compile(r'open\s*(.*)\d*')
    with open(nmap_outfile) as outf:
        for line in outf:
            if 'open' not in line:
                continue
            port = portpattern.findall(line)
            name = namepattern.findall(line)
            port = port[0] if port is not None else None
            name = name[0] if name is not None else None
            result[name] = {'port': port}
    return result


def print_result(result, json_out_file=None):
    '''打印最终结果'''
    if json_out_file is not None:
        with open(json_out_file, 'w') as out:
            json.dump(result, out)
    else:
        print('RESULT_START')
        print(json.dumps(result))
        print('RESULT_END')


def main(nmap_bin='/usr/bin/nmap'):
    parser = create_cmd_parser()
    args = parser.parse_args()
    nmap_bin = args.nmap_bin or nmap_bin
    setup_logger()
    _, outfile = tempfile.mkstemp()
    run_nmap(args.url, outfile, nmap_bin, ports=COMMON_PORTS)
    result = parse_nmap_result(outfile)
    print_result(result, args.json_out_file)


if __name__ == '__main__':
    main()
