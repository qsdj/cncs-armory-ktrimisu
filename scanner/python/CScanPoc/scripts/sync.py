# coding: utf-8

import os
import logging
import uuid
import getpass
import argparse
import imp
import importlib
import tempfile
import shutil
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

    parser.add_argument('--build-base-image',
                        dest='build_base_image',
                        help='POC 基础镜像，不指定该选项，将不进行 POC 执行镜像的编译')
    parser.add_argument('--force-rebuild', dest='force_rebuild', action='store_true',
                        help='是否强制重新编译镜像')
    # 默认值
    parser.set_defaults(poc=False, vuln=False, update=False,
                        verbose=False, very_verbose=False,
                        force_rebuild=False)

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


def create_image_build_context_dir(pocfile, base_image):
    context_dir = os.path.join(tempfile.gettempdir(), 'cscan-poc-build')
    if os.path.exists(context_dir):
        shutil.rmtree(context_dir)
    os.mkdir(context_dir)
    dockerfile = os.path.join(context_dir, 'Dockerfile')
    shutil.copyfile(pocfile, os.path.join(context_dir, 'main.py'))

    with open(dockerfile, 'w') as f:
        f.write('FROM {}\n'.format(base_image))
        f.write('COPY main.py /app/main.py\n')
        f.write('ENTRYPOINT [ "pipenv",  "run", "python", "main.py" ]')

    return context_dir


def sync_poc(poc, poc_file='', cnx=None, do_update=False, poc_image=None):
    try:
        s = SyncPoc(cnx, poc)
        if do_update:
            s.update()
        elif poc_image is not None:
            s.update_poc_image(poc_image)
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


def build_poc_image(poc, poc_file='', build_base='cscan-poc-base:0.1', cnx=None, force_rebuild=False):
    tag = build_base.split(':')
    tag = tag[1] if len(tag) == 2 else 'latest'
    if poc.poc_id is None or poc.poc_id.strip() == '':
        logger.warn('跳过 {} poc_id 不存在'.format(poc_file))

    build_context = create_image_build_context_dir(poc_file, build_base)
    poc_name = 'poc-{}:{}'.format(poc.poc_id, tag)
    cmd_image_exists = 'docker inspect --type=image {} >/dev/null 2>&1 '.format(poc_name)
    cmd = 'cd {} && docker build -t {} .'.format(build_context, poc_name)
    if not force_rebuild and os.system(cmd_image_exists) == 0:
        logger.debug('使用之前编译过的镜像缓存')
        return poc_name
    logger.info('Building image {}: {}'.format(poc_name, cmd))
    res = os.system(cmd)
    if res == 0:
        return poc_name
    else:
        logger.warn('镜像构建失败 {}'.format(poc_file))
        return None


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
        if args.build_base_image:
            img = build_poc_image(
                poc, poc_file, args.build_base_image, cnx, args.force_rebuild)
            if img is not None:
                sync_poc(poc, poc_file, cnx, False, img)
