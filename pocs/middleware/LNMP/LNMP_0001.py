# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'LNMP_0001'  # 平台漏洞编号，留空
    name = 'LNMP ftp控制面板安装程式未删除'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2013-12-08'  # 漏洞公布时间
    desc = '''
        LNMP一键环境包0.9中有个pureftpd的安装选项，安装时同时会安装一个PHP的控制面板。但是很少有人注意这个面板的有个install.php脚本。访问路径为 http://0day5.com/ftp/install.php
        这个安装脚本会在第五步让用户修改ftp面板的Admin用户的密码或添加ftp面板的管理员。
        添加成功后即可访问ftp的面板，接着我们就可以添加ftp的用户等一系列操作。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/913/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'LNMP'  # 漏洞应用名称
    product_version = 'LNMP一键环境包0.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bbf78993-982c-446d-851c-4f953c4a3693'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-14'  # POC创建时间

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

            # https://bugs.shuimugan.com/bug/view?bug_no=42162
            payload = '/ftp/install.php'
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and 'Configuration' in r.text and 'Step' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
