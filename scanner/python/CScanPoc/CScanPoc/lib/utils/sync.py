# coding: utf-8

import uuid
import os
import argparse
import mysql.connector
from datetime import datetime
from CScanPoc.lib.constants.product_type import get_product_type


class SyncError(Exception):
    def __init__(self, args):
        super(SyncError, self).__init__(args)


class SyncPoc:
    '''同步 POC 静态信息到数据库
    vuln.vuln_id 需要手工被添加
    '''

    def __init__(self):
        self.cnx = None

    def _poc_exists(self, poc_id):
        cursor = self.cnx.cursor(buffered=True)
        print "搜索 poc {0}".format(poc_id)
        try:
            cursor.execute(
                'SELECT count(*) FROM poc WHERE poc_id=%s',
                (poc_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print e
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
            print e
        finally:
            cursor.close()

    def _create_poc_vuln_map(self, poc_id, vuln_id):
        if self._poc_vuln_map_exists(poc_id, vuln_id):
            return
        cursor = self.cnx.cursor(buffered=True)
        try:
            cursor.execute(
                'INSERT INTO vuln_poc_mappings (poc_id, vuln_id) VALUES(%s, %s)',
                (poc_id, vuln_id))
            self.cnx.commit()
        except Exception as e:
            print e
        finally:
            cursor.close()

    def _pre_check_poc(self, poc):
        poc_id = poc.poc_id
        if poc_id is None or poc_id.strip() == '':
            raise SyncError('poc_id 为空')

    def run(self, args, poc, dbpasswd):
        '''
        args.host
        args.db
        args.user
        args.update
        '''
        if not self.cnx:
            self.cnx = mysql.connector.connect(
                user=args.user, password=dbpasswd, host=args.host, database=args.db)
        if args.update:
            self.update_poc(poc)
        else:
            self.insert_poc(poc)

    def insert_poc(self, poc):
        self._pre_check_poc(poc)
        if self._poc_exists(poc.poc_id):
            print 'poc 存在 [{0} id={1}]'.format(poc, poc.poc_id)
            return
        data = (
            poc.poc_id,
            poc.get_poc_name(),
            poc.author,
            poc.create_date)

        sql = ("INSERT INTO poc "
               "(poc_id, poc_name, author, create_time) "
               "VALUES(%s, %s, %s, %s)")
        cursor = self.cnx.cursor(buffered=True)
        print '插入 poc {0}'.format(poc)
        try:
            cursor.execute(sql, data)
            self.cnx.commit()
        except Exception as e:
            print '插入失败 {0}'.format(poc)
            print e
        finally:
            cursor.close()

        if poc.vuln and poc.vuln.vuln_id:
            self._create_poc_vuln_map(poc.poc_id, poc.vuln.vuln_id)

    def update_poc(self, poc):
        self._pre_check_poc(poc)
        if not self._poc_exists(poc.poc_id):
            print 'poc 不存在 [{0} id={1}]'.format(poc, poc.poc_id)
            return
        data = (
            poc.get_poc_name(),
            poc.author,
            poc.create_date,
            poc.poc_id)

        sql = ("UPDATE poc SET "
               "poc_name=%s, author=%s, create_time=%s "
               "WHERE poc_id=%s")
        cursor = self.cnx.cursor(buffered=True)
        try:
            print '更新 poc {0}'.format(poc)
            cursor.execute(sql, data)
        except Exception as e:
            print '更新 {0}'.format(poc)
            print e
        finally:
            cursor.close()
        if poc.vuln and poc.vuln.vuln_id:
            self._create_poc_vuln_map(poc.poc_id, poc.vuln.vuln_id)

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

    def __init__(self):
        self.cnx = None

    def _pre_check_vuln(self, vuln):
        vuln_id = vuln.vuln_id
        if vuln_id is None or vuln_id.strip() == '':
            raise SyncError('vuln_id 为空')

    def _vuln_exists(self, vuln_id):
        cursor = self.cnx.cursor(buffered=True)
        print "搜索漏洞 {0}".format(vuln_id)
        try:
            cursor.execute(
                'SELECT count(*) FROM vuln WHERE vuln_id=%s',
                (vuln_id,)
            )
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print e
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
            print '搜索组件 c_name={0} c_type={1}'.format(*data)
            sql = ("SELECT c_id FROM component WHERE c_name=%s AND c_type=%s")
            cursor.execute(sql, data)
            c_id = None
            if cursor.rowcount <= 0:
                print '创建组件 component c_name={0} c_type={1}'.format(*data)
                sql = ("INSERT INTO component "
                       "(c_id, c_name, c_type) "
                       "VALUES(%s, %s, %s)")
                c_id = str(uuid.uuid4())
                cursor.execute(sql, (c_id, product_name, product_type.name))
                self.cnx.commit()
            else:
                c_id = cursor.fetchone()[0]

            print '查询得 name={0} type={1} 得组件ID为 {2}'.format(
                product_name, product_type, c_id)
            return c_id
        except Exception as e:
            print '创建组件失败'
            print e
        finally:
            cursor.close()

    def run(self, args, vuln, dbpasswd):
        '''
        args.host
        args.db
        args.user
        args.update
        '''
        if not self.cnx:
            self.cnx = mysql.connector.connect(
                user=args.user, password=dbpasswd, host=args.host, database=args.db)
        if args.update:
            self.update_vuln(vuln)
        else:
            self.insert_vuln(vuln)

    def insert_vuln(self, vuln):
        self._pre_check_vuln(vuln)
        product_id = self._create_or_get_product(vuln.product)
        if self._vuln_exists(vuln.vuln_id):
            print '漏洞已经存在[{0} id={1}]'.format(vuln, vuln.vuln_id)
            return
        print '插入漏洞 {0}'.format(vuln)
        sql = ("INSERT INTO vuln "
               "(vuln_id, vuln_name, vuln_type,"
               " c_id, c_version,"
               " cve_id, disclosure_date, submit_time,"
               " level, source, detail) "
               "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        cursor = self.cnx.cursor(buffered=True)
        try:
            data = (
                vuln.vuln_id, vuln.name, vuln.type.value,
                product_id, vuln.product_version,
                vuln.cve_id, vuln.disclosure_date, datetime.now(),
                vuln.level.value, vuln.ref, vuln.desc
            )
            cursor.execute(sql, data)
        except Exception as e:
            print '插入漏洞失败{0}'.format(vuln)
            print e
        finally:
            cursor.close()
            self.cnx.commit()

    def update_vuln(self, vuln):
        '''根据 vuln_id 更新漏洞信息'''
        self._pre_check_vuln(vuln)
        product_id = self._create_or_get_product(vuln.product)
        cursor = self.cnx.cursor()
        try:
            sql = ("UPDATE vuln SET "
                   "vuln_name=%s, vuln_type=%s,"
                   "c_id=%s, c_version=%s,"
                   "cve_id=%s, disclosure_date=%s, submit_time=%s,"
                   "level=%s, source=%s, detail=%s"
                   "WHERE vuln_id=%s")
            cursor.execute(sql, (
                vuln.name, vuln.type.value,
                product_id, vuln.product_version,
                vuln.cve_id, vuln.disclosure_date, datetime.now(),
                vuln.level.value, vuln.ref, vuln.desc,
                vuln.vuln_id
            ))
        finally:
            cursor.close()
