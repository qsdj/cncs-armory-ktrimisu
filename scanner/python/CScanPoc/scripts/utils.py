# coding: utf-8

import os
import sys
import imp
import json
import uuid
import codecs
import shutil
import logging
import tempfile
import datetime
import importlib
import argparse
import mysql.connector
from CScanPoc import ABPoc, ABVuln
from CScanPoc.lib.constants.product_type import get_product_info
from CScanPoc.lib.utils.misc import vuln_to_dict, poc_to_dict, load_modules, find_vuln_poc


class INDEX_CONFIG:
    index_dir = 'index'

    if not os.path.exists(index_dir):
        os.makedirs(index_dir)

    @classmethod
    def __file(self, name, index_dir):
        d = INDEX_CONFIG.index_dir if index_dir is None else index_dir
        return os.path.join(d, name + '.index')

    @classmethod
    def get_poc_index_file(self, index_dir=None):
        return self.__file('poc', index_dir)

    @classmethod
    def get_vuln_index_file(self, index_dir=None):
        return self.__file('vuln', index_dir)

    @classmethod
    def get_poc_vuln_map_index_file(self, index_dir):
        return self.__file('poc_vuln_map', index_dir)


class CScanDb:

    def __init__(self, cnx, index_dir=None, update_poc_when_exists=False, update_vuln_when_exists=False, update_component_when_exists=False):
        self.cnx = cnx
        (self.vuln_ind, self.poc_ind, self.poc_vuln_ind) = load_index(index_dir)
        (self.update_poc_when_exists, self.update_vuln_when_exists, self.update_component_when_exists) = (
            update_poc_when_exists, update_vuln_when_exists, update_component_when_exists)

        self.component_synced = False
        self.d_component_name_id = None  # Dict<c_name, c_id>

        self.vuln_synced = False
        self.synced_vuln_ids_in_db = []

    def get_component_id(self, name):
        if not self.component_synced:
            self.sync_components()
        self.fetch_component_id_names()
        return self.d_component_name_id.get(name)

    def fetch_component_id_names(self):
        cursor = self.cnx.cursor(buffered=True)
        cursor.execute('SELECT c_id, c_name FROM component')
        result = cursor.fetchall()
        if self.component_synced:
            self.d_component_name_id = {}
            for i in result:
                self.d_component_name_id[i[1]] = i[0]
        return result

    def fetch_poc_and_related_vuln_ids(self):
        cursor = self.cnx.cursor(buffered=True)
        cursor.execute('SELECT poc_id, vuln_id FROM poc')
        return cursor.fetchall()

    def fetch_vuln_ids(self):
        cursor = self.cnx.cursor(buffered=True)
        cursor.execute('SELECT vuln_id FROM vuln')
        return map(lambda x: x[0], cursor.fetchall())

    def insert_component(self, component_name_set):
        if (len(component_name_set) == 0):
            return
        logging.info('开始插入 Component [count={}]'.format(
            len(component_name_set)))
        component_insert_sql = '''INSERT INTO component
            (c_id, c_name, c_first, c_type, `desc`, producer,
             properties, created_at, updated_at)
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)'''

        logging.info('准备要插入的 Component 数据')
        now = datetime.datetime.now()
        name_infos = filter(lambda name_info: name_info[1] is not None, map(
            lambda n: (n, get_product_info(n)), component_name_set))

        cursor = self.cnx.cursor()
        i = 0
        for (n, info) in name_infos:
            progress(i, len(name_infos), '插入组件')
            i += 1
            info['c_id'] = str(uuid.uuid4())
            info['type_str'] = info.get('type').name
            info['c_name'] = n
            info['created_at'] = now
            info['updated_at'] = now
            try:
                cursor.execute(component_insert_sql, map(lambda k: info.get(k), [
                    'c_id', 'c_name', 'name_pinyin_first', 'type_str', 'desc', 'producer', 'properties', 'created_at', 'updated_at']))
            except Exception as e:
                logging.warn('组件插入失败: {} {}\n{}'.format(n, info, e))
        self.cnx.commit()
        logging.info('成功插入 Component [count={}]'.format(
            len(component_name_set)))

    def update_component(self, component_name_set):
        if (len(component_name_set) == 0):
            return
        logging.info('更新 Component [count={}]'.format(len(component_name_set)))

        component_update_sql = '''UPDATE component
            SET c_first=%s, c_type=%s, `desc`=%s, producer=%s, properties=%s, updated_at=%s
            WHERE c_name=%s'''

        logging.info('准备要更新的 Component 数据')
        now = datetime.datetime.now()
        name_infos = filter(lambda name_info: name_info[1] is not None, map(
            lambda n: (n, get_product_info(n)), component_name_set))

        cursor = self.cnx.cursor()
        count = 0

        for (n, info) in name_infos:
            progress(count, len(name_infos), '更新组件')
            count += 1
            info['type_str'] = info.get('type').name
            info['c_name'] = n
            info['updated_at'] = now
            try:
                cursor.execute(component_update_sql, map(lambda k: info.get(k), [
                    'name_pinyin_first', 'type_str', 'desc', 'producer', 'properties', 'updated_at', 'c_name']))
            except Exception as e:
                logging.warn('Component 更新失败: {} {}\n{}'.format(n, info, e))

        self.cnx.commit()
        logging.info('成功更新 Component [count={}]'.format(
            len(component_name_set)))

    def insert_vuln(self, vuln_id_set):
        if (len(vuln_id_set) == 0):
            return
        logging.info('开始插入 Vuln [count={}]'.format(len(vuln_id_set)))

        vuln_insert_sql = '''INSERT INTO vuln
            (vuln_id, vuln_name, vuln_type, c_id, c_version, cve_id, disclosure_date,
             submit_time, level, source, detail, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

        logging.info('准备要插入的 Vuln 数据')
        vuln_infos = filter(lambda info: info is not None, map(
            lambda vuln_id: self.vuln_ind[vuln_id], vuln_id_set))
        now = datetime.datetime.now()
        cursor = self.cnx.cursor()
        count = 0

        for vuln_info in vuln_infos:
            progress(count, len(vuln_infos), '插入漏洞')
            count += 1
            c_id = self.get_component_id(vuln_info['product'])
            if c_id is None:
                continue
            vuln_info['c_id'] = c_id
            vuln_info['submit_time'] = now
            vuln_info['created_at'] = now
            vuln_info['updated_at'] = now
            try:
                cursor.execute(vuln_insert_sql, map(lambda k: vuln_info.get(k),
                                                    ['vuln_id', 'name', 'type', 'c_id', 'product_version',
                                                     'cve_id', 'disclosure_date', 'submit_time', 'level', 'ref', 'desc', 'created_at', 'updated_at']))
            except Exception as e:
                logging.warn('Vuln 插入失败: {}\n{}'.format(vuln_info, e))
        self.cnx.commit()
        logging.info('成功插入 Vuln [count={}]'.format(len(vuln_id_set)))

    def update_vuln(self, vuln_id_set):
        if (len(vuln_id_set) == 0):
            return
        logging.info('开始更新漏洞 [count={}]'.format(len(vuln_id_set)))
        vuln_update_sql = '''UPDATE vuln
            SET vuln_name=%s, vuln_type=%s, c_id=%s, c_version=%s, cve_id=%s, disclosure_date=%s, level=%s, source=%s, detail=%s, updated_at=%s
            WHERE vuln_id=%s'''

        logging.info('准备要更新的 Vuln 数据')
        vuln_infos = filter(lambda info: info is not None, map(
            lambda vuln_id: self.vuln_ind[vuln_id], vuln_id_set))
        now = datetime.datetime.now()
        count = 0
        cursor = self.cnx.cursor()

        for vuln_info in vuln_infos:
            progress(count, len(vuln_infos), '更新漏洞')
            count += 1
            c_id = self.get_component_id(vuln_info['product'])
            vuln_info['c_id'] = c_id
            vuln_info['updated_at'] = now
            try:
                cursor.execute(vuln_update_sql, map(lambda k: vuln_info.get(k), [
                    'name', 'type', 'c_id', 'product_version', 'cve_id', 'disclosure_date', 'level', 'ref', 'desc', 'updated_at', 'vuln_id']))
            except Exception as e:
                logging.warn('Vuln 更新失败: {}\n{}'.format(vuln_info, e))

        self.cnx.commit()
        logging.info('成功更新漏洞 [count={}]'.format(len(vuln_id_set)))

    def insert_pocs(self, poc_id_set):
        if (len(poc_id_set) == 0):
            return
        logging.info('开始插入 POC [count={}]'.format(len(poc_id_set)))

        self.sync_vuln(
            set(map(lambda poc_id: self.poc_vuln_ind[poc_id], poc_id_set)))

        poc_insert_sql = '''INSERT INTO poc
            (poc_id, poc_name, author, vuln_id, created_at, updated_at)
            VALUES(%s, %s, %s, %s, %s, %s)'''

        logging.info('准备要插入的 POC 数据')
        now = datetime.datetime.now()
        poc_infos = filter(lambda x: x is not None, map(
            lambda x: self.poc_ind[x], poc_id_set))
        count = 0
        cursor = self.cnx.cursor()

        for poc_info in poc_infos:
            progress(count, len(poc_infos), '插入 POC')
            count += 1
            vuln_id = self.poc_vuln_ind[poc_info['poc_id']]
            if vuln_id not in self.synced_vuln_ids_in_db:
                poc_info['vuln_id'] = None
            else:
                poc_info['vuln_id'] = vuln_id
            poc_info['created_at'] = now
            poc_info['updated_at'] = now

            try:
                cursor.execute(poc_insert_sql,
                               map(lambda k: poc_info.get(k), ['poc_id', 'name', 'author', 'vuln_id', 'created_at', 'updated_at']))
            except Exception as e:
                logging.warn('POC 插入失败: {}\n{}'.format(poc_info, e))

        self.cnx.commit()
        logging.info('成功插入 POC [count={}]'.format(len(poc_id_set)))

    def update_pocs(self, poc_id_set):
        if (len(poc_id_set) == 0):
            return
        logging.info('开始更新 POC [count={}]'.format(len(poc_id_set)))

        self.sync_vuln(
            set(map(lambda poc_id: self.poc_vuln_ind[poc_id], poc_id_set)))

        poc_update_sql = '''UPDATE poc
            SET poc_name=%s, author=%s, vuln_id=%s, updated_at=%s
            WHERE poc_id=%s'''

        logging.info('准备要更新的 POC 数据 [count={}]'.format(len(poc_id_set)))
        now = datetime.datetime.now()
        poc_infos = filter(lambda x: x is not None, map(
            lambda x: self.poc_ind[x], poc_id_set))
        count = 0
        cursor = self.cnx.cursor()

        for poc_info in poc_infos:
            progress(count, len(poc_infos), '更新 POC')
            count += 1
            vuln_id = self.poc_vuln_ind[poc_info['poc_id']]
            if vuln_id not in self.synced_vuln_ids_in_db:
                poc_info['vuln_id'] = None
            else:
                poc_info['vuln_id'] = vuln_id
            poc_info['updated_at'] = now
            try:
                cursor.execute(poc_update_sql,
                               map(lambda k: poc_info.get(k), ['name', 'author', 'vuln_id', 'updated_at', 'poc_id']))
            except Exception as e:
                logging.warn('POC 更新失败: {}\n{}\n{}'.format(
                    poc_info, e, poc_update_sql))

        self.cnx.commit()
        logging.info('成功更新 POC [count={}]'.format(len(poc_id_set)))

    def sync_components(self):
        logging.info('同步组件数据')
        existed_c_names = set(
            map(lambda x: x[1], self.fetch_component_id_names()))
        all_product_names = set(
            map(lambda x: x['product'], self.vuln_ind.values()))
        self.insert_component(all_product_names.difference(existed_c_names))
        if self.update_component_when_exists:
            self.update_component(
                all_product_names.intersection(existed_c_names))
        self.component_synced = True
        logging.info('完成组件数据同步')

    def sync_vuln(self, vuln_id_set):
        logging.info('同步 Vuln 数据')
        all_vuln_ids = set(self.vuln_ind.keys())
        existed_vuln_ids = self.fetch_vuln_ids()

        self.sync_components()

        self.insert_vuln(all_vuln_ids.difference(existed_vuln_ids))

        if self.update_vuln_when_exists:
            self.update_vuln(all_vuln_ids.intersection(existed_vuln_ids))

        self.vuln_synced = True
        self.synced_vuln_ids_in_db = self.fetch_vuln_ids()
        logging.info('完成漏洞数据同步')

    def sync_poc(self):
        logging.info('同步 POC 数据')
        existed_poc_vuln_ind = {}
        for item in self.fetch_poc_and_related_vuln_ids():
            existed_poc_vuln_ind[item[0]] = item[1]
        existed_poc_ids = set(existed_poc_vuln_ind.keys())
        all_poc_ids = set(self.poc_vuln_ind.keys())

        self.insert_pocs(all_poc_ids.difference(existed_poc_ids))

        if self.update_poc_when_exists:
            self.update_pocs(all_poc_ids.intersection(
                existed_poc_ids))
        logging.info('完成 POC 数据同步')


def progress(count, total, suffix=''):
    sys.stdout.write('%s [%s/%s]\r' % (suffix, count, total))
    sys.stdout.flush()


def sort_pocs(poc_base_dir):
    '''将 POC 放置到其检查的 产品类型/产品名 目录下'''
    def clean_up_poc_dirs(path):
        '''移除所有无用目录（空或者只有 .pyc 的目录）'''
        if not os.path.isdir(path):
            return

        # remove empty subfolders
        files = os.listdir(path)
        if len(files) != 0:
            for f in files:
                fullpath = os.path.join(path, f)
                if os.path.isdir(fullpath):
                    clean_up_poc_dirs(fullpath)
                elif fullpath.endswith('.pyc'):
                    os.remove(fullpath)
        # if folder empty, delete it
        if len(os.listdir(path)) == 0:
            logging.info('Remove empty dir: {}'.format(path))
            os.rmdir(path)

    mod_count = 0
    for (mod, d, file_name) in load_modules(poc_base_dir):
        mod_count += 1
        progress(mod_count, mod_count, '处理模块')
        (_, poc) = find_vuln_poc(mod)
        if poc is None or poc.vuln is None:
            continue
        prd = poc.vuln.product
        product_info = get_product_info(prd, False)
        if product_info is None:
            continue
        typ = product_info['type']
        should_be_in = os.path.join(
            poc_base_dir, typ.name, prd)

        if should_be_in != d:
            if not os.path.exists(should_be_in):
                os.makedirs(should_be_in)
            src_file = os.path.join(d, file_name)
            dst_file = os.path.join(should_be_in, file_name)
            logging.info('move from {} to {}'.format(src_file, dst_file))
            os.rename(src_file, dst_file)

    logging.info('Clean up poc dir: {}'.format(poc_base_dir))
    clean_up_poc_dirs(poc_base_dir)


def build_poc_image(poc, poc_file='', build_base='cscan-poc-base:0.1', cnx=None, force_rebuild=False, registry=None):
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

    tag = build_base.split(':')
    tag = tag[1] if len(tag) == 2 else 'latest'
    if poc.poc_id is None or poc.poc_id.strip() == '':
        logging.warn('跳过 {} poc_id 不存在'.format(poc_file))

    build_context = create_image_build_context_dir(poc_file, build_base)
    poc_name = 'poc-{}:{}'.format(poc.poc_id, tag)
    cmd_image_exists = 'docker inspect --type=image {} >/dev/null 2>&1 '.format(
        poc_name)
    cmd = 'cd {} && docker build -t {} .'.format(build_context, poc_name)
    if not force_rebuild and os.system(cmd_image_exists) == 0:
        logging.debug('使用之前编译过的镜像缓存')
        return poc_name
    logging.info('Building image {}: {}'.format(poc_name, cmd))
    res = os.system(cmd)
    if registry is not None:
        img = '{}/{}'.format(registry, poc_name)
    if res == 0:
        return poc_name
    else:
        logging.warn('镜像构建失败 {}'.format(poc_file))
        return None


def load_index(index_dir=None):
    '''
    :return: Tuple<Dict<vuln_id, vuln_dict>, Dict<poc_id, poc_dict>, Dict<poc_id, vuln_id>>
    '''
    def iter_ind(f):
        for line in file(f):
            if line is None or line.strip() == '':
                continue
            yield json.loads(line)

    vuln_ind = {}
    poc_ind = {}
    poc_vuln_ind = {}

    for i in iter_ind(INDEX_CONFIG.get_vuln_index_file(index_dir)):
        vuln_ind[i['vuln_id']] = i

    for i in iter_ind(INDEX_CONFIG.get_poc_index_file(index_dir)):
        poc_ind[i['poc_id']] = i

    for i in iter_ind(INDEX_CONFIG.get_poc_vuln_map_index_file(index_dir)):
        poc_vuln_ind[i[0]] = i[1]

    return (vuln_ind, poc_ind, poc_vuln_ind)


def indexing(poc_dir, index_dir=None):
    def write_obj(f, obj):
        f.write(json.dumps(obj))
        f.write('\n')
    (vuln_ind_file, poc_ind_file, poc_vuln_map_ind_file) = (
        INDEX_CONFIG.get_vuln_index_file(index_dir),
        INDEX_CONFIG.get_poc_index_file(index_dir),
        INDEX_CONFIG.get_poc_vuln_map_index_file(index_dir))

    vuln_ids = set({})
    poc_ids = set({})
    poc_vuln_rel = set({})

    with open(poc_ind_file, 'w') as poc_ind, open(vuln_ind_file, 'w') as vuln_ind, open(poc_vuln_map_ind_file, 'w') as poc_vuln_map_ind:
        mod_count = 0
        for (mod, _, _) in load_modules(poc_dir):
            progress(mod_count, mod_count, '处理模块')
            mod_count += 1
            (vuln, poc) = find_vuln_poc(mod)
            to_write_vulns = []
            to_write_poc = None
            if vuln and vuln.vuln_id not in vuln_ids:
                to_write_vulns.append(vuln)
            if poc and poc.poc_id not in poc_ids:
                to_write_poc = poc

                poc_vuln = poc.vuln
                if poc_vuln is not None and vuln is not None:
                    to_write_vulns.append(poc_vuln)

                    if poc_vuln.vuln_id is None or poc_vuln.vuln_id.strip() == '':
                        logging.warn('Vuln Id 为空 {}'.format(poc_vuln))
                    else:
                        rel = (poc.poc_id, poc_vuln.vuln_id)
                        if rel not in poc_vuln_rel:
                            write_obj(poc_vuln_map_ind, rel)
                            poc_vuln_rel.add(rel)

            for v in to_write_vulns:
                if v.vuln_id not in vuln_ids:
                    write_obj(vuln_ind, vuln_to_dict(vuln))
                    vuln_ids.add(vuln.vuln_id)
            if to_write_poc is not None:
                if to_write_poc.poc_id not in poc_ids:
                    write_obj(poc_ind, poc_to_dict(to_write_poc))
                    poc_ids.add(to_write_poc.poc_id)


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--sort', dest='sort',
                        action='store_true', help='整理 POC 将所有 POC 放置到 产品类型/产品名 目录中')
    # 数据库选项
    parser.add_argument('--host', dest="host", help="数据库地址")
    parser.add_argument("--user", dest="user", help="数据库用户")
    parser.add_argument('--db', dest="db", help="数据库名")
    parser.add_argument('--port', dest='port', help='数据库端口')
    parser.add_argument('--pass', dest="passwd", help="数据库密码")

    parser.add_argument('--poc-dir', dest='poc_dir', required=True,
                        help='目标目录，将递归处理目录下所有 .py 结尾文件')
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-vv', dest='very_verbose', action='store_true',
                        help='very verbose')

    parser.add_argument('--index-dir', dest='index_dir',
                        help='索引信息存放目录，默认当前目录 index 目录下')
    parser.add_argument('--skip-indexing', dest='skip_indexing',
                        action='store_true', help='创建索引')
    parser.add_argument('--update', dest='update',
                        action='store_true', help='如果数据存在，执行更新操作')

    parser.set_defaults(verbose=False, very_verbose=False, indexing=True,
                        update=False, host='localhost', user='root', db='cscan', passwd='', port=3306)

    return parser


def setup_logger(args):
    if args.very_verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)


def main():
    args = create_parser().parse_args()
    setup_logger(args)

    if args.sort:
        sort_pocs(args.poc_dir)
        return

    if not args.skip_indexing:
        logging.info('Indexing...')
        indexing(args.poc_dir)

    logging.info('Syncing...')
    cnx = mysql.connector.connect(
        user=args.user,
        password=args.passwd,
        host=args.host,
        database=args.db,
        port=args.port,
        charset='utf8')
    CScanDb(cnx,
            args.index_dir,
            args.update,
            args.update,
            args.update).sync_poc()


if __name__ == '__main__':
    main()
