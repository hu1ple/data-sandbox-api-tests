"""Shared account helpers and compatibility cases."""
from os import environ
import re

from catalog import case
from core import (
    Blocked, check, equal, field,
    id_segment as s, row, snapshot_ids, subset, utc,
)


def user(data):
    for k in ('id','displayName','organizationId'):
        field(data,k,str)
    for k in ('roles','permissions'):
        check(all(isinstance(v,str) for v in field(data,k,list)), f'{k} 包含非字符串')
    utc(data,'sessionExpiresAt')
    return data


def sandbox_path(value):
    return '/sandboxes/' + s(value)


def audit_has(c, target, actor=None, action=None):
    # keyword 的精确匹配策略可能依部署变化，audit_queries 由团队按日志索引设置。
    filters = c.values.get('audit_queries',{}).get(str(target),{})
    entries = c.all('/audit-logs',role='M',query={**filters,'result':'SUCCESS'})
    matches = [x for x in entries if x.get('targetId') == target and
               (actor is None or x.get('actorName') == actor) and
               (action is None or x.get('action') == action)]
    check(bool(matches),'未找到匹配操作者和目标的成功审计')
    for k in ('actorName','action','targetType','targetId','ip'):
        field(matches[0],k,str)


@case('TC-02-02', layer='业务', needs='bad_password unknown_account')
def bad_login(c):
    valid,_ = c.credentials('A')
    for name in (valid,c.fixture('unknown_account')):
        client = c.client(None)
        response=client.request('POST','/auth/dev-login',body={
            'username':name,'password':c.fixture('bad_password')
        })
        response.error(401,'INVALID_CREDENTIALS')
        check(re.search(r'[\u3400-\u9fff]',response.body['message']),'兼容错误提示未包含中文')
        client.request('GET','/me').error(401,'UNAUTHENTICATED')


@case('TC-02-03', layer='业务', remainder='空字段的精确 HTTP 与业务码见 G-20。')
def empty_credentials(c):
    name,password = c.credentials('A')
    for body in ({'username':'','password':password},{'username':name,'password':''}):
        client = c.client(None)
        client.request('POST','/auth/dev-login',body=body).error((400,401))
        client.request('GET','/me').error(401,'UNAUTHENTICATED')


@case('TC-04-02', layer='业务', remainder='用过期会话刷新真实前端，核对清会话及登录跳转。')
def expired_session(c):
    c.client(None).request('GET','/me').error(401,'UNAUTHENTICATED')
    expired = environ.get('SANDBOX_QA_EXPIRED_COOKIE')
    if not expired:
        raise Blocked('匿名请求断言通过。缺少 SANDBOX_QA_EXPIRED_COOKIE 以验证过期会话')
    c.client(None).request('GET','/me',cookie=expired).error(401,'UNAUTHENTICATED')


def account(c, body, valid=True):
    client = c.client(None)
    result = client.request('POST','/account-requests',body=body)
    if not valid:
        result.error(400)
        return
    data = result.success()
    field(data,'requestId',str)
    equal(field(data,'status',str),'PENDING','受理状态')
    utc(data,'submittedAt')
    return client


@case('TC-05-01', layer='业务', writes=True, needs='account_inputs bad_password',
      remainder='申请受理后的账号是否存在需由开通方核对。脚本只验证受理与后续登录未获得会话。')
def guest_account(c):
    for entry, kind in zip(c.many('account_inputs',2),('email','phone')):
        check(('@' in entry['contact']) == (kind=='email'),f'需 {kind} 类型的夹具')
        session = account(c,entry)
        session.request('POST','/auth/dev-login',
                        body={'username':entry['account'],'password':c.fixture('bad_password')}).error(401,'INVALID_CREDENTIALS')
        session.request('GET','/me').error(401,'UNAUTHENTICATED')


@case('TC-05-02', writes=True, needs='account_body')
def account_lengths(c):
    base = c.fixture('account_body')
    for value in ('A._-','A'*30,'A'*3,'A'*31,'qa@01','测qa01'):
        account(c,{**base,'account':value},valid=value in ('A._-','A'*30))


@case('TC-05-03', writes=True, needs='account_inputs')
def account_fields(c):
    variants = [
        ('contact','1380013800',False),('contact','qa@local',False),
        ('purpose','测'*9,False),('purpose','测'*10,True),
        ('purpose','测'*300,True),('purpose','测'*301,False),('organization','',False),
    ]
    for body,(k,v,valid) in zip(c.many('account_inputs',len(variants)),variants):
        account(c,{**body,k:v},valid)


@case('TC-05-05', layer='业务', writes=True, needs='account_body', remainder='账号申请查询接口未交付，拒绝后的受理记录需由联调方复查。')
def existing_account(c):
    name,_ = c.credentials('A')
    account(c,{**c.fixture('account_body'),'account':name},False)
    user(c.get('/me'))


def flavors(c):
    for fixture in c.many('flavor_projects',2):
        items = field(c.get('/resource-flavors',query={'projectId':fixture['projectId']}),'items',list)
        equal(snapshot_ids(items),snapshot_ids(fixture['items']),'项目规格集合')
        for expected in fixture['items']:
            actual = row(items,'id',expected['id'])
            subset(actual,expected,'规格')
            field(actual,'name',str)
            for k in ('cpuCores','memoryMiB','storageGiB'):
                field(actual,k,(int,float))
