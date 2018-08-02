# encoding: utf-8

import uuid
import json
import datetime
from pypinyin import Style, pinyin
from CScanPoc.lib.api.component import Component
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger
from .progress import progress
from .indexing import load_index


def __get_pinyin_first_letter(name):
    try:
        # https://github.com/mozillazg/python-pinyin
        return pinyin(name, style=Style.INITIALS, strict=False)[0][0][0].lower()
    except:
        return 'a'


def get_product_info(name):
    component = Component.get_component(name)
    return {
        'type': component.type.name,
        'producer': component.producer,
        'desc': component.description,
        'properties': json.dumps(
            component.property_schema.get('properties'),
            ensure_ascii=False),
        'name_pinyin_first': __get_pinyin_first_letter(name)
    }


class CScanDb:

    def __init__(self, cnx, index_dir=None, updating=False):
        self.cnx = cnx
        (self.vuln_ind, self.poc_ind, self.strategy_ind) = load_index(index_dir)
        self.poc_vuln_ind = {}
        for poc in self.poc_ind.values():
            if poc.get('poc_id') and poc.get('vuln_id'):
                self.poc_vuln_ind[poc.get('poc_id')] = poc.get('vuln_id')
        self.updating = updating
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
        return [x[0] for x in cursor.fetchall()]

    def fetch_strategy_ids(self):
        cursor = self.cnx.cursor(buffered=True)
        cursor.execute('SELECT strategy_id FROM strategy')
        return [x[0] for x in cursor.fetchall()]

    def insert_component(self, component_name_set):
        if (len(component_name_set) == 0):
            return
        logger.info('开始插入 Component [count={}]'.format(
            len(component_name_set)))
        component_insert_sql = '''INSERT INTO component
            (c_id, c_name, c_first, c_type, `desc`, producer,
             properties, created_at, updated_at)
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)'''

        logger.info('准备要插入的 Component 数据')
        now = datetime.datetime.now()
        name_infos = [name_info for name_info in [(n, get_product_info(
            n)) for n in component_name_set] if name_info[1] is not None]

        cursor = self.cnx.cursor()
        i = 0
        for (n, info) in name_infos:
            progress(i, len(name_infos), '插入组件')
            i += 1
            info['c_id'] = str(uuid.uuid4())
            info['c_name'] = n
            info['created_at'] = now
            info['updated_at'] = now
            try:
                cursor.execute(component_insert_sql, [info.get(k) for k in [
                    'c_id', 'c_name', 'name_pinyin_first', 'type', 'desc',
                    'producer', 'properties', 'created_at', 'updated_at']])
            except Exception as e:
                logger.warn('组件插入失败: {} {}\n{}'.format(n, info, e))
        self.cnx.commit()
        logger.info('成功插入 Component [count={}]'.format(
            len(component_name_set)))

    def update_component(self, component_name_set):
        if (len(component_name_set) == 0):
            return
        logger.info('更新 Component [count={}]'.format(len(component_name_set)))

        component_update_sql = '''UPDATE component
            SET c_first=%s, c_type=%s, `desc`=%s, producer=%s, properties=%s, updated_at=%s
            WHERE c_name=%s'''

        logger.info('准备要更新的 Component 数据')
        now = datetime.datetime.now()
        name_infos = [name_info for name_info in [(n, get_product_info(
            n)) for n in component_name_set] if name_info[1] is not None]

        cursor = self.cnx.cursor()
        count = 0

        for (n, info) in name_infos:
            progress(count, len(name_infos), '更新组件')
            count += 1
            info['c_name'] = n
            info['updated_at'] = now

            try:
                cursor.execute(component_update_sql, [info.get(k) for k in [
                    'name_pinyin_first', 'type', 'desc', 'producer',
                    'properties', 'updated_at', 'c_name']])
            except Exception as e:
                logger.warn('Component 更新失败: {} {}\n{}'.format(n, info, e))

        self.cnx.commit()
        logger.info('成功更新 Component [count={}]'.format(
            len(component_name_set)))

    def insert_vuln(self, vuln_id_set):
        if (len(vuln_id_set) == 0):
            return
        logger.info('开始插入 Vuln [count={}]'.format(len(vuln_id_set)))

        vuln_insert_sql = '''INSERT INTO vuln
            (vuln_id, vuln_name, vuln_type, c_id, c_version, cve_id, disclosure_date,
             submit_time, level, source, detail, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

        logger.info('准备要插入的 Vuln 数据')
        vuln_infos = [info for info in [self.vuln_ind[vuln_id]
                                        for vuln_id in vuln_id_set] if info is not None]
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
                cursor.execute(
                    vuln_insert_sql,
                    [vuln_info.get(k)
                     for k in ['vuln_id', 'name', 'type', 'c_id', 'product_version',
                               'cve_id', 'disclosure_date', 'submit_time', 'level',
                               'ref', 'desc', 'created_at', 'updated_at']])
            except Exception as e:
                logger.warn('Vuln 插入失败: {}\n{}'.format(vuln_info, e))
        self.cnx.commit()
        logger.info('成功插入 Vuln [count={}]'.format(len(vuln_id_set)))

    def update_vuln(self, vuln_id_set):
        if (len(vuln_id_set) == 0):
            return
        logger.info('开始更新漏洞 [count={}]'.format(len(vuln_id_set)))
        vuln_update_sql = '''UPDATE vuln
            SET vuln_name=%s, vuln_type=%s, c_id=%s, c_version=%s, cve_id=%s, disclosure_date=%s, level=%s, source=%s, detail=%s, updated_at=%s
            WHERE vuln_id=%s'''

        logger.info('准备要更新的 Vuln 数据')
        vuln_infos = [info for info in [self.vuln_ind[vuln_id]
                                        for vuln_id in vuln_id_set] if info is not None]
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
                cursor.execute(vuln_update_sql, [vuln_info.get(k) for k in [
                    'name', 'type', 'c_id', 'product_version', 'cve_id', 'disclosure_date', 'level', 'ref', 'desc', 'updated_at', 'vuln_id']])
            except Exception as e:
                logger.warn('Vuln 更新失败: {}\n{}'.format(vuln_info, e))

        self.cnx.commit()
        logger.info('成功更新漏洞 [count={}]'.format(len(vuln_id_set)))

    def update_strategies(self, strategy_id_set):
        if not strategy_id_set:
            return
        strategy_update_sql = '''UPDATE strategy
            SET strategy_name=%s, author=%s, `desc`=%s, create_time=%s, updated_at=%s
            WHERE strategy_id=%s'''
        count = 0
        successful_count = 0
        cursor = self.cnx.cursor()
        for info in [x for x in [self.strategy_ind[x]
                                 for x in strategy_id_set]
                     if x is not None]:
            progress(count, len(strategy_id_set),
                     '更新策略 {}'.format(info.get('strategy_id')))
            info['updated_at'] = datetime.datetime.now()
            try:
                cursor.execute(strategy_update_sql,
                               [info.get(k) for k in
                                ['name', 'author', 'desc', 'create_date',
                                 'updated_at', 'strategy_id']])
                successful_count += 1
            except Exception as err:
                logger.warning('策略更新失败：%s\n%s', info, err)
        self.cnx.commit()
        logger.info('成功更新策略【%s个】', successful_count)

    def insert_strategies(self, strategy_id_set):
        if not strategy_id_set:
            return
        logger.info('开始插入策略【%s】', len(strategy_id_set))

        strategy_insert_sql = '''INSERT INTO strategy
            (strategy_id, strategy_name, author, `desc`, create_time, created_at, updated_at)
            VALUES(%s, %s, %s, %s, %s, %s, %s)'''

        now = datetime.datetime.now()

        count = 0
        successful_count = 0
        cursor = self.cnx.cursor()
        for info in [x for x in [self.strategy_ind[x]
                                 for x in strategy_id_set]
                     if x is not None]:
            progress(count, len(strategy_id_set),
                     '插入策略 {}'.format(info.get('strategy_id')))
            info['created_at'] = now
            info['updated_at'] = now
            try:
                cursor.execute(strategy_insert_sql,
                               [info.get(k) for k in
                                ['strategy_id', 'name', 'author', 'desc',
                                 'create_date', 'created_at', 'updated_at']])
                successful_count += 1
            except Exception as err:
                logger.warning('策略插入失败：%s\n%s', info, err)
        self.cnx.commit()
        logger.info('成功插入策略【%s个】', successful_count)

    def insert_pocs(self, poc_id_set):
        if not poc_id_set:
            return
        logger.info('开始插入 POC [count={}]'.format(len(poc_id_set)))

        self.sync_vuln(
            set([self.poc_vuln_ind[poc_id] for poc_id in poc_id_set]))

        poc_insert_sql = '''INSERT INTO poc
            (poc_id, poc_name, author, vuln_id, created_at, updated_at, args)
            VALUES(%s, %s, %s, %s, %s, %s, %s)'''

        logger.info('准备要插入的 POC 数据')
        now = datetime.datetime.now()
        poc_infos = [x for x in [self.poc_ind[x]
                                 for x in poc_id_set] if x is not None]
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
                               [poc_info.get(k) for k in
                                ['poc_id', 'name', 'author', 'vuln_id',
                                 'created_at', 'updated_at', 'args']])
            except Exception as err:
                logger.warning('POC 插入失败: {}\n{}'.format(poc_info, err))

        self.cnx.commit()
        logger.info('成功插入 POC [count={}]'.format(len(poc_id_set)))

    def update_pocs(self, poc_id_set):
        if (len(poc_id_set) == 0):
            return
        logger.info('开始更新 POC [count={}]'.format(len(poc_id_set)))

        self.sync_vuln(
            set([self.poc_vuln_ind[poc_id] for poc_id in poc_id_set]))

        poc_update_sql = '''UPDATE poc
            SET poc_name=%s, author=%s, vuln_id=%s, updated_at=%s, args=%s
            WHERE poc_id=%s'''

        logger.info('准备要更新的 POC 数据 [count={}]'.format(len(poc_id_set)))
        now = datetime.datetime.now()
        poc_infos = [x for x in [self.poc_ind[x]
                                 for x in poc_id_set] if x is not None]
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
                               [poc_info.get(k) for k in
                                ['name', 'author', 'vuln_id',
                                 'updated_at', 'args', 'poc_id']])
            except Exception as e:
                logger.warn('POC 更新失败: {}\n{}\n{}'.format(
                    poc_info, e, poc_update_sql))

        self.cnx.commit()
        logger.info('成功更新 POC [count={}]'.format(len(poc_id_set)))

    def sync_components(self):
        logger.info('同步组件数据')
        existed_c_names = set(
            [x[1] for x in self.fetch_component_id_names()])
        all_product_names = set(
            [x['product'] for x in list(self.vuln_ind.values())])
        for common_component in Component.get_common_components():
            logger.info('通用组件：%s', common_component)
            all_product_names.add(common_component)
        self.insert_component(all_product_names.difference(existed_c_names))
        if self.updating:
            self.update_component(
                all_product_names.intersection(existed_c_names))
        self.component_synced = True
        logger.info('完成组件数据同步')

    def sync_vuln(self, vuln_id_set):
        logger.info('同步 Vuln 数据')
        all_vuln_ids = set(self.vuln_ind.keys())
        existed_vuln_ids = self.fetch_vuln_ids()

        self.sync_components()

        self.insert_vuln(all_vuln_ids.difference(existed_vuln_ids))

        if self.updating:
            self.update_vuln(all_vuln_ids.intersection(existed_vuln_ids))

        self.vuln_synced = True
        self.synced_vuln_ids_in_db = self.fetch_vuln_ids()
        logger.info('完成漏洞数据同步')

    def sync_poc(self):
        logger.info('同步 POC 数据')
        existed_poc_vuln_ind = {}
        for item in self.fetch_poc_and_related_vuln_ids():
            existed_poc_vuln_ind[item[0]] = item[1]
        existed_poc_ids = set(existed_poc_vuln_ind.keys())
        all_poc_ids = set(self.poc_vuln_ind.keys())

        self.insert_pocs(all_poc_ids.difference(existed_poc_ids))

        if self.updating:
            self.update_pocs(all_poc_ids.intersection(
                existed_poc_ids))
        logger.info('完成 POC 数据同步')

    def sync_strategy(self):
        logger.info('同步策略数据')
        existed_strategy_ids = set(self.fetch_strategy_ids())
        all_strategy_ids = set(self.strategy_ind.keys())

        self.insert_strategies(
            all_strategy_ids.difference(existed_strategy_ids))

        if self.updating:
            self.update_strategies(
                all_strategy_ids.intersection(existed_strategy_ids))
