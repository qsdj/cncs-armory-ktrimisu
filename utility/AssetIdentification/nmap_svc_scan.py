#!/usr/bin/python
# coding: utf-8

import argparse
import json
import logging
import os
import re
import tempfile
from urlparse import urlparse

from common import COMMON_PORTS
from common import create_cmd_parser as create_common_cmd_parser
from common import print_result, setup_logger

NMAP_CMD = "{nmap_bin} -p {ports} -oN {output_file} {hosts}"


def run_nmap(host_or_url, outfile, nmap_bin, ports=COMMON_PORTS):
    """执行 nmap 进行服务扫描"""
    parsed = urlparse(host_or_url)
    host = host_or_url
    if parsed.scheme:
        host = parsed.netloc
    if isinstance(ports, (set, list, tuple)):
        ports = ",".join([str(x) for x in ports])
    cmd = NMAP_CMD.format(
        nmap_bin=nmap_bin, ports=ports, output_file=outfile, hosts=host
    )
    logging.info("执行: %s", cmd)
    os.system(cmd)


def create_cmd_parser():
    parser = create_common_cmd_parser()
    parser.add_argument(
        "--nmap-bin", required=False, dest="nmap_bin", help="NMAP 二进制文件"
    )
    return parser


def parse_nmap_result(nmap_outfile):
    result = {}
    portpattern = re.compile(r"(\d+)/")
    namepattern = re.compile(r"open\s*(.*)\d*")
    with open(nmap_outfile) as outf:
        for line in outf:
            if "open" not in line:
                continue
            port = portpattern.findall(line)
            name = namepattern.findall(line)
            port = port[0] if port is not None else None
            name = name[0] if name is not None else None
            result[name] = {"port": port}
    return result


def main(nmap_bin="/usr/bin/nmap"):
    parser = create_cmd_parser()
    args = parser.parse_args()
    nmap_bin = args.nmap_bin or nmap_bin
    setup_logger()
    _, outfile = tempfile.mkstemp()
    run_nmap(args.url, outfile, nmap_bin, ports=COMMON_PORTS)
    result = parse_nmap_result(outfile)
    print_result(result, args.json_out_file)


if __name__ == "__main__":
    main()
