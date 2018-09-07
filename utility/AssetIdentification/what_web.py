#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import logging
import tempfile
from urlparse import urlparse

from common import create_cmd_parser, print_result, setup_logger

WHAT_WEB_CMD = "{what_web_bin} {url} --log-json {output_file}"


def _safe_lower(s):
    try:
        return s.lower()
    except:
        return s


def run_whatweb(url, outfile, what_web_bin):
    cmd = WHAT_WEB_CMD.format(
        what_web_bin=what_web_bin, url=url, output_file=outfile)
    logging.info("执行: %s", cmd)
    os.system(cmd)


class WhatWebResultParser(object):
    """whatweb 结果解析"""

    def __init__(self, whatweb_outfile, name_trans={}):
        with open(whatweb_outfile) as outfile:
            self.whatweb_result = json.load(outfile)
        self.components = {}
        self.name_trans = name_trans
        self.has_attr_MetaGenerator = False

    def parse(self):
        for item in self.whatweb_result:
            self._parse_one(item)
        return self.components

    def _trans(self, name):
        '''转译组件名'''
        return self.name_trans.get(_safe_lower(name), name)

    def _parse_one(self, json_obj):
        """解析某个结果"""
        logging.debug("解析：%s", json_obj)
        if json_obj == {}:
            return
        target = json_obj["target"]
        pth = urlparse(target).path
        plugins = json_obj["plugins"]
        for name in plugins:
            name = name.encode('utf-8')
            if name in ("HTTPServer", "X-Powered-By"):
                self._parse_common(plugins[name])
            elif name == "MetaGenerator":
                self.has_attr_MetaGenerator = True
                self._parse_meta_generator(plugins[name], pth)
            elif not self.has_attr_MetaGenerator and (
                    _safe_lower(name) in self.name_trans):
                name = name.decode('utf-8')
                self._parse_in_plugins_common(plugins[name], name)

    def _parse_in_plugins_common(self, json_obj, name):
        """组件结果 直接显示在plugins里"""
        version = json_obj.get("version", "")
        name = self._trans(name)
        info = self.components.get(name, {})
        if version:
            info["version"] = version
        self.components[name] = info

    def _parse_common(self, json_obj):
        """结果为 组件名/版本 的形式的结果的解析"""
        if json_obj.get("os", []):
            self.components["os"] = json_obj.get("os", [])[0]

        for item in json_obj.get("string", []):
            item = item.split(" ")[0]
            (name, version) = (item, None)
            if "/" in item:
                name, version = item.split("/", 1)
            elif "(" in item:
                name, _version = item.split("(")
                version = _version.split(")")[0]
            name = self._trans(name)
            info = self.components.get(name, {})
            if version:
                info["version"] = version
            self.components[name] = info

    def _parse_meta_generator(self, json_obj, pth=None):
        """MetaGenerator 结果的解析"""
        for item in json_obj.get("string", []):
            if ('by' not in item.lower()):
                (name, version) = (item, None)
                if " " in item:
                    (name, version) = item.split(" ", 1)
                elif "." in item:
                    name = item.split(".")[0]
                # name = item.split(" ")[0]
                name = self._trans(name)
                info = self.components.get(name, {})
                if version:
                    info["version"] = version
                info["deploy_path"] = pth or "/"
                self.components[name] = info


def main(what_web_bin="WhatWeb/whatweb"):
    parser = create_cmd_parser()
    args = parser.parse_args()
    setup_logger()
    _, outfile = tempfile.mkstemp()
    name_trans = {}
    for line in open('component_names'):
        line = line.strip()
        name_trans[_safe_lower(line)] = line
    run_whatweb(args.url, outfile, what_web_bin)
    result = WhatWebResultParser(outfile, name_trans=name_trans).parse()
    print_result(result, args.json_out_file)


if __name__ == "__main__":
    main()
