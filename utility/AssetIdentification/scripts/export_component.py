#!/usr/bin/env python3
# coding:utf-8

import os
import json
import argparse
from collections import defaultdict


def create_cmd_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-r', '--run', required=False, dest='func_name',
        help='输入功能函数名')
    parser.add_argument(
        '-i', '--input', required=False, dest='input_file',
        help='输入component_path')
    parser.add_argument(
        '-o', '--out-file', required=False, dest='out_file',
        help='输出结果到文件')
    return parser


def export_components(args):
    '''
    导出component 组件名称 到component_names
    '''
    component_path = args.input_file if args.input_file else None
    output_filename = args.out_file if args.out_file else "../component_names"

    if component_path:
        all_components = (component.split(".json")[0] for component in os.listdir(
            component_path) if component.endswith(".json"))
        with open(output_filename, 'w') as tmp:
            for line in sorted(all_components):
                tmp.write(line+"\n")


def export_whatweb(args):
    '''
    导出whatweb 插件名称 到 output_filename(默认为 ./what_web_plugins )
    '''
    whatweb_runpath = "../WhatWeb/whatweb"

    output_filename = args.out_file if args.out_file else "./what_web_plugins"

    os.system("{} -l > {}".format(whatweb_runpath, output_filename))
    total = int(
        os.popen("cat {}|wc -l".format(output_filename)).read().split("\n")[0].lstrip())
    count = 1
    contents = list()
    with open(output_filename, 'r') as tmp1:
        for line in tmp1:
            if count > 4 and count < total - 9:
                contents.append(line.split(" ")[0]+"\n")
            count += 1

    with open(output_filename, 'w') as tmp:
        for line in contents:
            tmp.write(line)

def export_cms_components(args):
    '''
    导出 组件类型为cms的组件名 到 ./cms_component_names
    '''
    component_path = args.input_file if args.input_file else None
    output_filename = args.out_file if args.out_file else "./cms_component_names"

    _output_data = []
    if component_path:
        for component in os.listdir(component_path):
            if component.endswith(".json"):
                with open(component_path+component, 'r') as _tmpdata:
                    _data = json.load(_tmpdata)
                    if _data["type"] == "cms":
                        _output_data.append(component.split(".json")[0])
        with open(output_filename, 'w') as _output:
            for data in sorted(_output_data):
                _output.write(data+"\n")



def error_print():
    func_name = [export_components, export_whatweb, export_cms_components]
    print("需要参数-r指定执行函数名\n部分函数名/功能如下：")
    for _func in func_name:
        print(_func.__name__+":"+_func.__doc__)

# def get_has_space():
#     '''
#     输出components.txt 中含有空格的组件
#     '''
#     with open("./components.txt", 'r') as components:
#         for line in components:
#             tmpline = line.split("\n")[0]
#             if " " in tmpline:
#                 print(tmpline)

# def find_like_component():
#     '''
#     输出components.txt 与 components.txt相似的组件名
#     '''
#     with open("./what_web.txt", "r") as tmp:
#         what_web_pluins = [line.split("\n")[0] for line in tmp.readlines()]
#     tmp = defaultdict(list)
#     with open("./components.txt", 'r') as components:
#         for line in components:
#             tmpline = line.split("\n")[0].upper()
#             if " " in tmpline:
#                 tmpline = tmpline.split(" ")[0]
#             elif "CMS" in tmpline:
#                 if tmpline.endswith("CMS"):
#                     tmpline = tmpline.split("CMS")[0]
#                 if tmpline.startswith("CMS"):
#                     tmpline = tmpline.split("CMS")[1]
#             for plugin in what_web_pluins:
#                 if tmpline in plugin.upper() and not tmpline == plugin.upper():
#                     tmp[line.split("\n")[0]].append(plugin)
#     for a in tmp.keys():
#         print(a)
#         for b in tmp[a]:
#             print("    "+b)


def main():
    '''
    解析命令行执行响应的函数
    '''
    _parser = create_cmd_parser()
    args = _parser.parse_args()
    if args.func_name:
        if args.func_name == "export_components":
            export_components(args)
        elif args.func_name == "export_whatweb":
            export_whatweb(args)
        elif args.func_name == "export_cms_components":
            export_cms_components(args)
        else:
            error_print()
    else:
        error_print()


if __name__ == "__main__":
    main()
    # python3 export_component.py -r export_cms_components -i ~/work/CScan-POC/CScanPoc/CScanPoc/resources/component/
    # python3 export_component.py -r export_components -i ~/work/CScan-POC/CScanPoc/CScanPoc/resources/component
    # python3 export_component.py -r export_whatweb