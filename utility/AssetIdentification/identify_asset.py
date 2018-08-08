#!/usr/bin/env python
# coding: utf-8
import copy
import logging
import tempfile

from common import COMMON_PORTS
from common import create_cmd_parser as create_common_cmd_parser
from common import print_result, setup_logger
from nmap_svc_scan import parse_nmap_result, run_nmap
from what_web import WhatWebResultParser, run_whatweb


def create_cmd_parser():
    parser = create_common_cmd_parser()
    parser.add_argument(
        '--nmap-bin', required=False, dest='nmap_bin',
        help='NMAP 二进制文件')
    return parser


def main(what_web_bin='WhatWeb/whatweb', nmap_bin='/usr/bin/nmap'):
    parser = create_cmd_parser()
    args = parser.parse_args()
    setup_logger()

    nmap_bin = args.nmap_bin or nmap_bin

    logging.info('使用 WhatWeb 进行扫描')
    _, whatweb_outfile = tempfile.mkstemp()
    run_whatweb(args.url, whatweb_outfile, what_web_bin)
    whatweb_result = WhatWebResultParser(whatweb_outfile).parse()

    logging.info('使用 NMAP 进行扫描')
    _, nmap_outfile = tempfile.mkstemp()
    run_nmap(args.url, nmap_outfile, nmap_bin, ports=COMMON_PORTS)
    nmap_result = parse_nmap_result(nmap_outfile)

    logging.info('合并扫描结果')
    result = copy.deepcopy(nmap_result)
    for component in whatweb_result:
        props = result.get(component, whatweb_result[component])
        if component not in result:
            result[component] = props
        else:
            for prop in props:
                result[component][prop] = props[prop]

    print_result(result, args.json_out_file)


if __name__ == '__main__':
    main()
