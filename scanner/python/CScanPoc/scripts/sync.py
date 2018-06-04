# coding: utf-8

import os
import logging
import uuid
import getpass
import argparse
import imp
import importlib
import mysql.connector
from CScanPoc import ABPoc, ABVuln
from CScanPoc.lib.utils.sync import SyncPoc, SyncVuln

logger = logging.getLogger('sync')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    # 数据库选项
    parser.add_argument('--host', dest="host",
                        required=True, help="数据库地址")
    parser.add_argument("--user", dest="user",
                        required=True, help="数据库用户")
    parser.add_argument('--db', dest="db", required=True, help="数据库名")
    parser.add_argument('--pass', dest="passwd", help="数据库密码")

    # 更新/插入
    parser.add_argument('--update', dest='update',
                        action='store_true', help='执行更新操作')
    parser.add_argument('--insert', dest='update',
                        action='store_false', help='执行插入操作')

    # 操作对象 poc/vuln
    parser.add_argument('--poc', dest='poc', action='store_true',
                        help='设定 poc 为操作对象，可以和 --vuln 选项同时使用')
    parser.add_argument('--vuln', dest='vuln', action='store_true',
                        help='设定 vuln 为操作对象，可以和 --poc 选项同时使用')

    # 操作对象地址
    parser.add_argument('--target', dest='target', required=True,
                        help='目标目录/文件')

    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-vv', dest='very_verbose', action='store_true',
                        help='very verbose')

    # 默认值
    parser.set_defaults(poc=False, vuln=False, update=False,
                        verbose=True, very_verbose=False)

    return parser


def add_poc_id(poc_file):
    '''为文件中 POC 添加 poc_id 属性'''
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


def get_module(poc_file, create_poc_id=False):
    '''
    :return: Tuple<Vuln, Poc, string_poc_file>
    '''
    if not os.path.isfile(poc_file) or not poc_file.endswith('.py'):
        logger.warn('不是 Python 源文件 {}'.format(poc_file))
        return
    mod_name = '{}-{}'.format(
        os.path.basename(poc_file).rstrip('.py'),
        str(uuid.uuid4())
    ).replace('.', '_')

    try:
        logger.debug('加载 {}'.format(poc_file))
        foo = imp.load_source('CScanPoc.{}'.format(mod_name), poc_file)
        poc = None
        vuln = None
        for attr in dir(foo):
            try:
                val = getattr(foo, attr)()
                if isinstance(val, ABPoc):
                    poc = val
                elif isinstance(val, ABVuln):
                    vuln = val
            except:
                continue
        return (vuln, poc, poc_file)
    except Exception as e:
        logger.warn('加载失败 {}'.format(poc_file))
        raise e


def get_modules(poc_file_or_dir, create_poc_id=False):
    '''
    :return: List<Tuple<Vuln, Poc, string_poc_file>>
    '''
    if os.path.isfile(poc_file_or_dir):
        return [get_module(poc_file_or_dir, create_poc_id)]
    elif not os.path.isdir(poc_file_or_dir):
        logger.warn('目标不是文件/目录')
        return

    result = []
    for f in os.listdir(poc_file_or_dir):
        if not f.endswith('.py') or f == '__init__.py':
            continue
        poc_file = os.path.join(poc_file_or_dir, f)
        try:
            result.append(get_module(poc_file))
        except Exception as e:
            logger.warn('导入失败 {}:\n%s'.format(poc_file), e)
    return result


def sync_poc(poc, poc_file='', cnx=None, do_update=False):
    try:
        s = SyncPoc(cnx, poc)
        if do_update:
            s.update()
        else:
            s.insert()
    except Exception as e:
        logger.warn('同步 {} 失败[update={}]：{}\n%s'.format(
            poc, do_update, poc_file), e)


def sync_vuln(vuln, poc_file='', cnx=None, do_update=False):
    try:
        s = SyncVuln(cnx, vuln)
        if do_update:
            s.update()
        else:
            s.insert()
    except Exception as e:
        logger.warn('同步 {} 失败[update={}]：{}\n%s'.format(
            vuln, do_update, poc_file), e)


if __name__ == '__main__':
    args = create_parser().parse_args()

    if args.very_verbose:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)

    passwd = args.passwd
    if passwd is None:
        passwd = getpass.getpass('输入数据库密码：')
    cnx = mysql.connector.connect(
        user=args.user, password=passwd, host=args.host, database=args.db)

    vuln_poc_list = get_modules(args.target)

    for (vuln, poc, poc_file) in vuln_poc_list:
        if args.poc:
            sync_poc(poc, poc_file, cnx, args.update)
        if args.vuln:
            sync_vuln(vuln, poc_file, cnx, args.update)
