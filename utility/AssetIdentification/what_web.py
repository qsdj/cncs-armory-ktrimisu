#!/usr/bin/python
# coding: utf-8

import os
import json
import logging
import tempfile
from urlparse import urlparse

from common import create_cmd_parser, print_result, setup_logger

WHAT_WEB_CMD = "{what_web_bin} {url} --log-json {output_file}"


def run_whatweb(url, outfile, what_web_bin):
    cmd = WHAT_WEB_CMD.format(what_web_bin=what_web_bin, url=url, output_file=outfile)
    logging.info("执行: %s", cmd)
    os.system(cmd)


class WhatWebResultParser(object):
    """whatweb 结果解析"""

    def __init__(self, whatweb_outfile):
        with open(whatweb_outfile) as outfile:
            self.whatweb_result = json.load(outfile)
        self.components = {}

        self.has_attr_MetaGenerator = False
        self.component_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "component")
        self.all_components = [component.split(".json")[0] for component in os.listdir(self.component_path) if component.endswith(".json")]
        self.upper_all_components = [component.upper() for component in self.all_components]

    def parse(self):
        for item in self.whatweb_result:
            self._parse_one(item)
        return self.components

    def _parse_one(self, json_obj):
        """解析某个结果"""
        logging.debug("解析：%s", json_obj)
        if json_obj == {}:
            return
        target = json_obj["target"]
        pth = urlparse(target).path
        plugins = json_obj["plugins"]
        for name in plugins:
            if name in ("HTTPServer", "X-Powered-By"):
                self._parse_common(plugins[name])
            elif name == "MetaGenerator":
                self.has_attr_MetaGenerator = True
                self._parse_meta_generator(plugins[name], pth)
            elif not self.has_attr_MetaGenerator and (name.upper() in self.upper_all_components):
                self._parse_in_plugins_common(plugins[name], name)


    def _parse_in_plugins_common(self, json_obj, name):
        """组件结果 直接显示在plugins里"""
        version = json_obj.get("version", "")
        name = self._common_name_calibration(name)
        info = self.components.get(name, {})
        if version:
            info["version"] = version
        self.components[name] = info

    def _parse_common(self, json_obj):
        """结果为 组件名/版本 的形式的结果的解析"""
        for item in json_obj.get("string", []):
            item = item.split(" ")[0]
            (name, version) = (item, None)
            if "/" in item:
                name, version = item.split("/", 1)
            elif "(" in item:
                name, _version = item.split("(")
                version = _version.split(")")[0]
            name = self._common_name_calibration(name)
            info = self.components.get(name, {})
            if version:
                info["version"] = version
            self.components[name] = info

    def _common_name_calibration(self, name):
        '''转译组件名'''
        for component in self.all_components:
            if name.upper() in component.upper():
                return component
            else:
                return name

    def _parse_meta_generator(self, json_obj, pth=None):
        """MetaGenerator 结果的解析"""
        for item in json_obj.get("string", []):
            (name, version) = (item, None)
            if " " in item:
                (name, version) = item.split(" ", 1)
            elif "." in item:
                name = item.split(".")[0]
            # name = item.split(" ")[0]
            name = self._common_name_calibration(name)
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
    run_whatweb(args.url, outfile, what_web_bin)
    result = WhatWebResultParser(outfile).parse()
    print_result(result, args.json_out_file)


if __name__ == "__main__":
    main()
