# coding: utf-8

import uuid
import os
import inspect
import logging
import argparse
import mysql.connector
from datetime import datetime
from CScanPoc import ABPoc, ABVuln
from CScanPoc.lib.constants.product_type import get_product_type


logger = logging.getLogger('sync')


class SyncError(Exception):
    pass


class SyncPoc:
    '''同步 POC 静态信息到数据库
    vuln.vuln_id 需要手工被添加
    '''

    def __init__(self, cnx, poc):
        self.cnx = cnx
        self.poc = poc

    def _poc_exists(self, poc_id):
        cursor = self.cnx.cursor(buffered=True)
        logger.info('搜索 Poc[id={}]'.format(poc_id))
        try:
            cursor.execute(
                'SELECT count(*) FROM poc WHERE poc_id=%s',
                (poc_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            raise SyncError({
                'message': '检查 poc_id={} 是否在数据库存在失败'.format(poc_id),
                'exception': e})
        finally:
            cursor.close()

    def _poc_vuln_map_exists(self, poc_id, vuln_id):
        cursor = self.cnx.cursor(buffered=True)
        try:
            cursor.execute(
                'SELECT count(*) FROM vuln_poc_mappings WHERE poc_id=%s AND vuln_id=%s',
                (poc_id, vuln_id))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            raise SyncError({
                'message': '检查 poc_id={} vuln_id={} 映射在数据库是否存在失败'.format(poc_id, vuln_id),
                'exception': e})
        finally:
            cursor.close()

    def _create_poc_vuln_map(self, poc_id, vuln_id):
        if self._poc_vuln_map_exists(poc_id, vuln_id):
            logger.info('poc_id={} vuln_id={} 映射已存在'.format(poc_id, vuln_id))
            return
        logger.info('创建 poc_id={} vuln_id={} 的映射'.format(poc_id, vuln_id))
        cursor = self.cnx.cursor(buffered=True)
        try:
            cursor.execute(
                'INSERT INTO vuln_poc_mappings (poc_id, vuln_id) VALUES(%s, %s)',
                (poc_id, vuln_id))
            self.cnx.commit()
        except Exception as e:
            logger.warning(
                '创建 poc_id={} vuln_id={} 映射失败'.format(poc_id, vuln_id))
            raise SyncError({
                'message': '创建 poc_id={} vuln_id={} 映射失败'.format(poc_id, vuln_id),
                'exception': e})
        finally:
            cursor.close()

    def _pre_check_poc(self, poc):
        if not isinstance(poc, ABPoc):
            raise SyncError({
                'message': '{} 不是 poc'.format(poc)})

        poc_id = poc.poc_id
        if poc_id is None or poc_id.strip() == '':
            raise SyncError({
                'message': '{} 的 poc_id 为空'.format(poc)})

    def insert(self):
        self._pre_check_poc(self.poc)
        if self._poc_exists(self.poc.poc_id):
            logger.info('{} 在数据库中已经存在'.format(self.poc))
            return
        data = (
            self.poc.poc_id,
            self.poc.get_poc_name(),
            self.poc.author,
            self.poc.create_date)

        sql = ("INSERT INTO poc "
               "(poc_id, poc_name, author, create_time) "
               "VALUES(%s, %s, %s, %s)")
        cursor = self.cnx.cursor(buffered=True)
        logger.info('插入 {}'.format(self.poc))
        try:
            cursor.execute(sql, data)
            self.cnx.commit()
        except Exception as e:
            logger.warning('插入失败 {}\n%s'.format(self.poc), e)
        finally:
            cursor.close()

        if self.poc.vuln and self.poc.vuln.vuln_id:
            self._create_poc_vuln_map(self.poc.poc_id, self.poc.vuln.vuln_id)

    def update(self):
        self._pre_check_poc(self.poc)
        if not self._poc_exists(self.poc.poc_id):
            logger.warn('{} 在数据库中不存在'.format(self.poc))
            return
        data = (
            self.poc.get_poc_name(),
            self.poc.author,
            self.poc.create_date,
            self.poc.poc_id)

        sql = ("UPDATE poc SET "
               "poc_name=%s, author=%s, create_time=%s "
               "WHERE poc_id=%s")
        cursor = self.cnx.cursor(buffered=True)
        logger.info('更新 {}'.format(self.poc))
        try:
            cursor.execute(sql, data)
            self.cnx.commit()
        except Exception as e:
            logger.warn('更新失败 {}\n%s'.format(self.poc), e)
            return
        finally:
            cursor.close()

        if self.poc.vuln and self.poc.vuln.vuln_id:
            self._create_poc_vuln_map(self.poc.poc_id, self.poc.vuln.vuln_id)

    def update_poc_image(self, image_name):
        self._pre_check_poc(self.poc)
        if not self._poc_exists(self.poc.poc_id):
            logger.warn('{} 在数据库中不存在'.format(self.poc))
            return
        data = (image_name, self.poc.poc_id)

        sql = ("UPDATE poc SET "
               "image_name=%s "
               "WHERE poc_id=%s")
        cursor = self.cnx.cursor(buffered=True)
        logger.info('更新 {} image_name={}'.format(self.poc, image_name))
        try:
            cursor.execute(sql, data)
            self.cnx.commit()
        except Exception as e:
            logger.warn('更新失败 {} image_name={}\n%s'.format(self.poc, image_name), e)
            return
        finally:
            cursor.close()


class SyncVuln:
    '''同步 POC 静态信息到数据库
    注意：
    - vuln.vuln_id 需要手工被添加
    - 组件类型需要用户手工指定，可选有： 'cms','os','middleware','database','device'

    插入：
    1. 查看漏洞对应组件是否存在，不存在则插入（ vuln.produc_name 即数据库 component.c_name，
       c_name 和 c_type 唯一确定组件）
    2. 插入漏洞信息，如果相同 poc_id 的漏洞存在，抛出异常

    更新：
    1. 和插入一样，漏洞对应组件如果不存在则先插入
    2. 根据 poc_id 更新数据
    '''

    def __init__(self, cnx, vuln):
        self.cnx = cnx
        self.vuln = vuln

    def _pre_check_vuln(self, vuln):
        if not isinstance(vuln, ABVuln):
            raise SyncError({
                'message': '{} 不是 ABVuln'.format(vuln)})

        vuln_id = vuln.vuln_id
        if vuln_id is None or vuln_id.strip() == '':
            raise SyncError({
                'message': '{} 的 vuln_id 为空'.format(vuln)})

    def _vuln_exists(self, vuln_id):
        cursor = self.cnx.cursor(buffered=True)
        logger.info('搜索 vuln_id={}'.format(vuln_id))
        try:
            cursor.execute(
                'SELECT count(*) FROM vuln WHERE vuln_id=%s',
                (vuln_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            raise SyncError({
                'message': 'vuln_id={} 的漏洞搜索失败'.format(vuln_id),
                'exception': e})
        finally:
            cursor.close()

    def _create_or_get_product(self, product_name):
        '''如果不存在则创建

        :return: 组件 id
        '''
        product_type = get_product_type(product_name)
        cursor = self.cnx.cursor(buffered=True)
        try:
            data = (product_name, product_type.name)
            logger.info('搜索组件 c_name={} c_type={}'.format(*data))

            sql = ("SELECT c_id FROM component WHERE c_name=%s AND c_type=%s")
            cursor.execute(sql, data)
            c_id = None
            if cursor.rowcount <= 0:
                logger.info('创建组件 component c_name={} c_type={}'.format(*data))
                sql = ("INSERT INTO component "
                       "(c_id, c_name, c_type) "
                       "VALUES(%s, %s, %s)")
                c_id = str(uuid.uuid4())
                cursor.execute(sql, (c_id, product_name, product_type.name))
                self.cnx.commit()
            else:
                c_id = cursor.fetchone()[0]

            logger.info('搜索得组件ID={} [c_name={} c_type={}]'.format(
                        c_id, product_name, product_type))
            return c_id
        except Exception as e:
            logger.warning('搜索/创建组件失败 c_name={} c_type={}'.format(*data))
            raise SyncError({
                'message': '搜索/创建组件 c_name={} c_type={}'.format(*data),
                'exception': e})
        finally:
            cursor.close()

    def insert(self):
        vuln = self.vuln
        self._pre_check_vuln(vuln)

        if self._vuln_exists(vuln.vuln_id):
            logger.info('{} 漏洞已存在'.format(vuln))
            return

        product_id = self._create_or_get_product(vuln.product)
        logger.info('插入漏洞 %s', vuln)
        sql = ("INSERT INTO vuln "
               "(vuln_id, vuln_name, vuln_type,"
               " c_id, c_version,"
               " cve_id, cnvd_id, disclosure_date, submit_time,"
               " level, source, detail) "
               "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        cursor = self.cnx.cursor(buffered=True)
        try:
            data = (
                vuln.vuln_id, vuln.name, vuln.type.value,
                product_id, vuln.product_version,
                vuln.cve_id, vuln.cnvd_id, vuln.disclosure_date, datetime.now(),
                vuln.level.value, vuln.ref, vuln.desc)
            cursor.execute(sql, data)
            self.cnx.commit()
        except Exception as e:
            logger.warning('{} 漏洞插入失败'.format(vuln))
            raise SyncError({
                'message': '漏洞插入失败 {}'.format(vuln),
                'exception': e})
        finally:
            cursor.close()

    def update(self):
        '''根据 vuln_id 更新漏洞信息'''
        vuln = self.vuln
        self._pre_check_vuln(vuln)
        product_id = self._create_or_get_product(vuln.product)
        logger.info('更新漏洞 {}'.format(vuln))
        cursor = self.cnx.cursor()
        try:
            sql = ("UPDATE vuln SET "
                   "vuln_name=%s, vuln_type=%s,"
                   "c_id=%s, c_version=%s,"
                   "cve_id=%s, cnvd_id=%s, disclosure_date=%s, submit_time=%s,"
                   "level=%s, source=%s, detail=%s"
                   "WHERE vuln_id=%s")
            cursor.execute(sql, (
                vuln.name, vuln.type.value,
                product_id, vuln.product_version,
                vuln.cve_id, vuln.cnvd_id, vuln.disclosure_date, datetime.now(),
                vuln.level.value, vuln.ref, vuln.desc,
                vuln.vuln_id))
            self.cnx.commit()
        except Exception as e:
            logger.warning('{} 漏洞更新失败'.format(vuln))
            raise SyncError({
                'message': '漏洞更新失败 {}'.format(vuln),
                'exception': e})
        finally:
            cursor.close()
