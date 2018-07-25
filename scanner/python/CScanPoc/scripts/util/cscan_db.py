# encoding: utf-8

import uuid
import json
import logging
import datetime
from progress import progress
from indexing import load_index
from CScanPoc.lib.constants.product_type import get_product_info


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
            info['properties']
            if info.get('properties') is not None:
                info['properties'] = json.dumps(info.get('properties'))
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
            if info.get('properties') is not None:
                info['properties'] = json.dumps(info.get('properties'))
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
            (poc_id, poc_name, author, vuln_id, created_at, updated_at, args)
            VALUES(%s, %s, %s, %s, %s, %s, %s)'''

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
            poc_info['args'] = poc_info.get('option_schema', None)

            try:
                cursor.execute(poc_insert_sql,
                               map(lambda k: poc_info.get(k), ['poc_id', 'name', 'author', 'vuln_id', 'created_at', 'updated_at', 'args']))
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
            SET poc_name=%s, author=%s, vuln_id=%s, updated_at=%s, args=%s
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
            poc_info['args'] = poc_info.get('option_schema', None)
            try:
                cursor.execute(poc_update_sql,
                               map(lambda k: poc_info.get(k), ['name', 'author', 'vuln_id', 'updated_at', 'args', 'poc_id']))
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
