# coding: utf-8

import os
import uuid
import getpass
import argparse
import imp
import importlib
import mysql.connector
from CScanPoc.lib.utils import sync


def __add_db_arguments(parser):
    parser.add_argument('--host', dest="host",
                        required=True, help="数据库地址")
    parser.add_argument("--user", dest="user",
                        required=True, help="数据库用户")
    parser.add_argument('--db', dest="db", required=True, help="数据库名")
    parser.add_argument('--pass', dest="passwd", help="数据库密码")


def __add_update_option(parser):
    parser.add_argument('--update', dest='update', action='store_true')
    parser.add_argument('--insert', dest='update', action='store_false')
    parser.set_defaults(update=False)


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers(dest='subparsers')

    parser_vuln = subparsers.add_parser('vuln')
    __add_db_arguments(parser_vuln)
    __add_update_option(parser_vuln)
    parser_vuln.add_argument('--vuln_name', dest="vuln_name",
                             help="漏洞类名，从 pocs 目录开始，如 Joomla_0001.Vuln")

    parser_poc = subparsers.add_parser('poc')
    __add_db_arguments(parser_poc)
    __add_update_option(parser_poc)
    parser_poc.add_argument('--poc_name', dest="poc_name",
                            help="poc 类名，从 pocs 目录开始，如 Joomla_0001.Poc")

    parser_all = subparsers.add_parser('all')
    __add_db_arguments(parser_all)
    __add_update_option(parser_all)
    parser_all.add_argument('--poc-dir', dest='poc_dir')
    parser_all.add_argument('--poc-only', dest='poc_only', action='store_true')
    parser_all.add_argument(
        '--vuln-only', dest='vuln_only', action='store_true')

    subparsers.add_parser('uuid')
    return parser


def add_poc_id(poc_file):
    lines = open(poc_file, 'r').readlines()
    new_lines = []
    for line in lines:
        if 'poc_id' in line:
            return
        new_lines.append(line)
        if '(ABPoc):' in line:
            new_lines.append('    poc_id = \'{0}\'\n'.format(uuid.uuid4()))
    with open(poc_file, 'w') as f:
        f.writelines(new_lines)


def get_all_modules(poc_dir, create_poc_id=False):
    result = []
    for f in os.listdir(poc_dir):
        if f == '__init__.py':
            continue
        poc_file = os.path.join(poc_dir, f)
        try:
            foo = imp.load_source(
                'CScanPoc.{0}'.format(f.rstrip('.py')), poc_file)
            poc_id = foo.Poc().poc_id
            if poc_id is None or poc_id.strip() == '':
                foo = None
                add_poc_id(poc_file)
                foo = imp.load_source(
                    'CScanPoc.{0}'.format(f.rstrip('.py')), poc_file)

            result.append((foo.Vuln(), foo.Poc(), poc_file))
        except Exception as e:
            print 'Import Error: {0}\n{1}'.format(poc_file, e)
    return result


def sync_poc(args, poc, dbpasswd, poc_file='', cnx=None):
    try:
        s = sync.SyncPoc()
        if cnx is not None:
            s.cnx = cnx
        s.run(args, poc, dbpasswd)
    except Exception as e:
        print '同步 {0} 失败：{1}\n{2}'.format(poc, poc_file, e)


def sync_vuln(args, vuln, dbpasswd, poc_file='', cnx=None):
    try:
        s = sync.SyncVuln()
        if cnx is not None:
            s.cnx = cnx
        s.run(args, vuln, passwd)
    except Exception as e:
        print '同步 {0} 失败：{1}\n{2}'.format(vuln, poc_file, e)


if __name__ == '__main__':
    args = create_parser().parse_args()
    if args.subparsers in ['vuln', 'poc', 'all']:
        passwd = args.passwd
        if passwd is None:
            passwd = getpass.getpass('输入数据库密码：')
        cnx = mysql.connector.connect(
            user=args.user, password=passwd, host=args.host, database=args.db)

    if args.subparsers == 'vuln':
        vuln_name = args.vuln_name
        (f, n) = vuln_name.split('.')
        vuln = getattr(importlib.import_module('CScanPoc.pocs.' + f), n)()
        sync_vuln(args, vuln, passwd, cnx)
    elif args.subparsers == 'poc':
        poc_name = args.poc_name
        (f, n) = poc_name.split('.')
        poc = getattr(importlib.import_module('CScanPoc.pocs.' + f), n)()
        sync_poc(args, poc, passwd, cnx)
    elif args.subparsers == 'all':
        vuln_poc_list = get_all_modules(args.poc_dir)
        print '================= 开始同步 =================='
        for (vuln, poc, poc_file) in vuln_poc_list:
            if args.poc_only:
                sync_poc(args, poc, passwd, poc_file, cnx)
            elif args.vuln_only:
                sync_vuln(args, vuln, passwd, poc_file, cnx)
            else:
                sync_vuln(args, vuln, passwd, poc_file, cnx)
                sync_poc(args, poc, passwd, poc_file, cnx)
    elif args.subparsers == 'uuid':
        print uuid.uuid4()
