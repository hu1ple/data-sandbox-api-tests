"""Authentication, metadata, sandbox and membership scripts."""
from copy import deepcopy
from os import environ

from catalog import case
from core import (
    ADMIN, ANALYST, Blocked, absent, check, enum, equal, field, forbid_fields,
    id_segment as s, row, snapshot_ids, subset, unique, utc,
)

SBX = {'REQUESTED','PROVISIONING','ACTIVE','DEGRADED','STOPPED','FAILED','TERMINATING','TERMINATED','REJECTED'}
ENV = {'REQUESTED','PROVISIONING','RUNNING','STOPPING','STOPPED','STARTING','FAILED','TERMINATING','TERMINATED','SIMULATED_READY'}
PRIVATE = {'phone','phonenumber','mobile','mobilephone','contact','email'}


def user(data):
    for k in ('id','displayName','organizationId'):
        field(data,k,str)
    for k in ('roles','permissions'):
        check(all(isinstance(v,str) for v in field(data,k,list)), f'{k} 包含非字符串')
    utc(data,'sessionExpiresAt')
    return data


def environment(data):
    field(data,'id',str)
    enum(data,'type',{'DEBUG','PRODUCTION'})
    enum(data,'status',ENV)
    enum(data,'runtimeMode',{'REAL','MOCK'})
    field(data,'imageId',str)
    field(data,'readinessVerified',bool)
    field(data,'allowedActions',list)
    utc(data,'statusObservedAt')
    return data


def sandbox(data):
    for k in ('id','name','purpose','ownerId','projectId','approvalId'):
        field(data,k,str)
    for k in ('version','approvalVersion'):
        field(data,k,int)
    enum(data,'approvalStatus',{'PENDING','APPROVED','REJECTED'})
    enum(data,'lifecycleStatus',SBX)
    utc(data,'createdAt')
    utc(data,'expiresAt',nullable=True)
    field(data,'allowedActions',list)
    for env in field(data,'environments',list):
        environment(env)
        field(env,'flavor',dict)
    return data


def sandbox_path(value):
    return '/sandboxes/' + s(value)


def status(c, sandbox_id, role='A'):
    obj = c.get(sandbox_path(sandbox_id)+'/status',role=role)
    equal(field(obj,'sandboxId',str),sandbox_id,'状态所属沙箱')
    enum(obj,'lifecycleStatus',SBX)
    enum(obj,'approvalStatus',{'PENDING','APPROVED','REJECTED'})
    utc(obj,'updatedAt')
    for env in field(obj,'environments',list):
        environment(env)
    return obj


def members(c, sid, role='A'):
    return c.array(sandbox_path(sid)+'/members',role=role)


def member_requests(c, sid):
    return c.array(sandbox_path(sid)+'/member-requests')


def member_create(c, sid, body, key=None):
    result = c.send('POST', sandbox_path(sid)+'/member-requests', body=body, key=key or unique()).success()
    field(result,'approvalId',str)
    subset(result, {'status':'PENDING','sandboxId':sid}, '加人申请')
    return result


def sbx_create(c, payload, key=None):
    result = sandbox(c.send('POST','/sandboxes',body=payload,key=key or unique()).success())
    subset(result,{'approvalStatus':'PENDING','lifecycleStatus':'REQUESTED','projectId':payload['projectId']})
    return result


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


@case('TC-01-01')
def anonymous_csrf(c):
    client = c.client(None)
    check(bool(client.csrf()), '匿名 CSRF 凭据为空')
    expected = user(client.login(*c.credentials('A')))
    equal(user(client.request('GET','/me').success())['id'],expected['id'],'同会话登录身份')


@case('TC-01-02', layer='业务', writes=True)
def csrf_rejection(c):
    admin = c.client('M')
    other = c.client('A')
    with c.saved_settings() as before:
        body = {**before,'defaultSandboxDays':45 if before['defaultSandboxDays']!=45 else 46}
        first = c.get('/settings',role='M')
        for token in (None,'bogus',other.csrf()):
            response = admin.request('PUT','/settings',body=body,csrf=token)
            response.error(403)
            check('CSRF' in response.code,'错误码不含 CSRF')
            equal(c.get('/settings',role='M'),first,'拒绝后的配置')


@case('TC-02-01')
def login_roles(c):
    ids = set()
    for role, label in [('A','ANALYST'),('M','PLATFORM_ADMIN')]:
        session = c.client(None)
        logged = user(session.login(*c.credentials(role)))
        current = user(session.request('GET','/me').success())
        check(label in logged['roles'],f'{role} 登录角色不符')
        subset(current,{k:logged[k] for k in ('id','roles','permissions')},'当前会话')
        ids.add(logged['id'])
    equal(len(ids),2,'两个测试身份数量')


@case('TC-02-02', layer='业务', needs='bad_password unknown_account')
def bad_login(c):
    valid,_ = c.credentials('A')
    for name in (valid,c.fixture('unknown_account')):
        client = c.client(None)
        client.request('POST','/auth/dev-login',body={
            'username':name,'password':c.fixture('bad_password')
        }).error(401,'INVALID_CREDENTIALS')
        client.request('GET','/me').error(401,'UNAUTHENTICATED')


@case('TC-02-03', layer='业务', remainder='空字段的精确 HTTP 与业务码见 G-20。')
def empty_credentials(c):
    name,password = c.credentials('A')
    for body in ({'username':'','password':password},{'username':name,'password':''}):
        client = c.client(None)
        client.request('POST','/auth/dev-login',body=body).error((400,401))
        client.request('GET','/me').error(401,'UNAUTHENTICATED')


@case('TC-03-01', layer='业务', remainder='页头退出、清 sessionStorage 和跳转需在浏览器复查。空响应精确形态见 G-16。')
def logout(c):
    client = c.client('A')
    old = client.export_cookie()
    client.request('POST','/auth/logout').empty_success()
    client.request('GET','/me').error(401,'UNAUTHENTICATED')
    c.client(None).request('GET','/me',cookie=old).error(401,'UNAUTHENTICATED')


@case('TC-04-01', remainder='用两个角色在浏览器核对菜单显隐。')
def permissions(c):
    a = user(c.get('/me'))
    m = user(c.get('/me',role='M'))
    check('ANALYST' in a['roles'] and 'PLATFORM_ADMIN' in m['roles'],'测试角色不符')
    check(ANALYST <= set(a['permissions']),'分析员缺少约定权限')
    check(not ADMIN.intersection(a['permissions']),'分析员获得管理权限')
    check(ADMIN <= set(m['permissions']),'管理员缺少约定权限')


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


@case('TC-06-01', layer='业务', needs='project_keyword project_free_ids project_excluded_ids')
def eligible_projects(c):
    query = {'keyword':c.fixture('project_keyword')}
    items = c.all('/projects',query=query)
    equal(snapshot_ids(items),sorted(c.fixture('project_free_ids')),'可建项目集合')
    for bad in c.fixture('project_excluded_ids'):
        absent(items,'id',bad)
    for item in items:
        field(item,'name',str)
        field(item,'allowedActions',list)
        if 'authorizationExpiresAt' in item:
            utc(item,'authorizationExpiresAt',nullable=True)
    data = c.page('/projects',query={'keyword':unique()})
    equal((data['items'],data['total']),([],0),'空项目页')


@case('TC-07-01', needs='flavor_projects')
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


@case('TC-08-01', needs='image_samples')
def images(c):
    expected = c.fixture('image_samples')
    for kind in ('DEBUG','PRODUCTION'):
        items = field(c.get('/engine-images',query={'environmentType':kind}),'items',list)
        check(bool(items),'预置镜像未返回')
        for item in items:
            equal(item.get('environmentType'),kind,'环境类型')
            for k in ('id','name','version'):
                field(item,k,str)
            field(item,'tools',list)
        subset(row(items,'id',expected[kind]['id']),expected[kind],'镜像')


@case('TC-09-01', needs='sandbox_filter sandbox_filter_ids')
def sandbox_pages(c):
    pages = [c.page('/sandboxes',query={'page':n,'pageSize':2}) for n in (1,2)]
    equal(pages[0]['total'],pages[1]['total'],'两页总数')
    check(pages[0]['total']>=3,'本用例需要至少三个可见沙箱')
    check(not set(snapshot_ids(pages[0]['items'])) & set(snapshot_ids(pages[1]['items'])),'跨页记录重复')
    query = c.fixture('sandbox_filter')
    result = c.all('/sandboxes',query=query)
    equal(snapshot_ids(result),sorted(c.fixture('sandbox_filter_ids')),'组合筛选结果')
    for item in result:
        subset(item,{k:query[k] for k in ('projectId','lifecycleStatus') if k in query})
        field(item,'environments',list)
        field(item,'allowedActions',list)
    equal(c.page('/sandboxes',query={'keyword':unique()})['total'],0,'无匹配项目总数')


@case('TC-09-02', remainder='超出末页的 HTTP 口径待 G-17 确认，报告记录实际响应。')
def default_pagination(c):
    data = c.page('/sandboxes')
    equal((data['page'],data['pageSize']),(1,20),'默认分页')
    check(data['total']>=21,'本用例需要至少 21 个可见沙箱')
    tail = c.send('GET','/sandboxes',query={'page':9999,'pageSize':20})
    if tail.status == 200:
        equal(field(tail.success(),'items',list),[],'超末页数据')
    else:
        tail.error((400,404,422))


@case('TC-10-01', needs='sandbox_owned sandbox_pending')
def details(c):
    for key in ('sandbox_owned','sandbox_pending'):
        target = c.fixture(key)
        data = sandbox(c.get(sandbox_path(target)))
        equal(data['id'],target,'沙箱 ID')
        if key == 'sandbox_pending':
            subset(data,{'lifecycleStatus':'REQUESTED','approvalStatus':'PENDING'})


@case('TC-10-02', layer='业务', needs='sandbox_other')
def hidden_sandbox(c):
    hidden = c.fixture('sandbox_other')
    equal(c.get(sandbox_path(hidden),role='OTHER').get('id'),hidden,'他人沙箱存在')
    for target in (hidden,unique()):
        c.send('GET',sandbox_path(target)).error(404,'SANDBOX_NOT_FOUND')


@case('TC-11-01', needs='sandbox_provisioning', remainder='中间态可用联调事件或控速确认，轮询采样可能跳过中间态。')
def status_poll(c):
    sid = c.fixture('sandbox_provisioning')
    observed = c.poll(lambda:status(c,sid),lambda x:x['lifecycleStatus']=='ACTIVE','沙箱 ACTIVE')
    detail = sandbox(c.get(sandbox_path(sid)))
    for k in ('lifecycleStatus','approvalStatus'):
        equal(observed[k],detail[k],k)
    equal({e['id']:e['status'] for e in observed['environments']},
          {e['id']:e['status'] for e in detail['environments']},'环境状态')


@case('TC-12-01', layer='业务', writes=True, needs='sandbox_body')
def create_pending(c):
    created = sbx_create(c,c.fixture('sandbox_body'))
    equal(created['ownerId'],user(c.get('/me'))['id'],'沙箱申请人')
    detail = c.get(sandbox_path(created['id']))
    subset(detail,{'approvalStatus':'PENDING','lifecycleStatus':'REQUESTED'})
    check(all(env.get('status') not in ('RUNNING','SIMULATED_READY') for env in detail['environments']),'审批前已开通环境')
    items = c.all('/approvals',role='M',query={'kind':'SANDBOX_CREATE','status':'PENDING','keyword':created['name']})
    subset(row(items,'approvalId',created['approvalId']),{'targetId':created['id']})


def rejected_sandbox(c, body, statuses):
    project = body.get('projectId')
    if not project:
        raise Blocked('沙箱校验夹具须提供 projectId')
    current = c.all('/sandboxes',query={'projectId':project})
    def approvals():
        return c.all('/approvals',role='M',query={'kind':'SANDBOX_CREATE'})
    before = snapshot_ids(approvals(),'approvalId')
    c.send('POST','/sandboxes',body=body,key=unique()).error(statuses)
    equal(snapshot_ids(c.all('/sandboxes',query={'projectId':project})),snapshot_ids(current),'沙箱写入')
    equal(snapshot_ids(approvals(),'approvalId'),before,'审批写入')


@case('TC-12-02', writes=True, needs='sandbox_inputs')
def sandbox_text_boundaries(c):
    variants = [('name','',False),('name','测'*50,True),('name','测'*51,False),
                ('purpose','',False),('purpose','测'*500,True),('purpose','测'*501,False)]
    for body,(k,value,ok) in zip(c.many('sandbox_inputs',len(variants)),variants):
        payload = {**body,k:value}
        if ok:
            sbx_create(c,payload)
        else:
            rejected_sandbox(c,payload,400)


@case('TC-12-03', writes=True, needs='sandbox_inputs')
def sandbox_day_bounds(c):
    days = (0,1,365,366,1.5)
    for body,value in zip(c.many('sandbox_inputs',len(days)),days):
        payload = {**body,'durationDays':value}
        if value in (1,365):
            sbx_create(c,payload)
        else:
            rejected_sandbox(c,payload,400)


@case('TC-12-04', writes=True, needs='sandbox_body')
def sandbox_environment_fields(c):
    original = c.fixture('sandbox_body')
    empty = {**original,'environments':[]}
    rejected_sandbox(c,empty,400)
    for k in ('flavorId','imageId','type'):
        body = deepcopy(original)
        if k == 'type':
            body['environments'][0][k] = 'STAGING'
        else:
            body['environments'][0].pop(k,None)
        rejected_sandbox(c,body,400)


@case('TC-12-05', layer='业务', writes=True, needs='sandbox_ineligible_inputs')
def projects_not_eligible(c):
    for body in c.many('sandbox_ineligible_inputs',2):
        rejected_sandbox(c,body,(400,403,404,409,422))


@case('TC-12-06', layer='业务', writes=True, needs='sandbox_authorization_inputs')
def authorization_limit(c):
    near,over = c.many('sandbox_authorization_inputs',2)
    sbx_create(c,{**near,'durationDays':29})
    rejected_sandbox(c,{**over,'durationDays':31},(400,409,422))


@case('TC-12-07', layer='业务', writes=True, needs='sandbox_body')
def sandbox_concurrent(c):
    base = c.fixture('sandbox_body')
    clients = [c.client('A',fresh=True) for _ in range(2)]
    check(len(base['name']) <= 49,'并发夹具名称须为追加 1 位数字留空间')
    for client in clients:
        client.csrf()
    requests = [
        lambda client=client,n=n:client.request('POST','/sandboxes',key=unique(),
                                                 body={**base,'name':base['name']+str(n)})
        for n,client in enumerate(clients)
    ]
    first,second = sorted(c.parallel(requests),key=lambda x:x.status)
    created = sandbox(first.success())
    second.error(409)
    items = c.all('/sandboxes',query={'projectId':base['projectId']})
    equal(snapshot_ids(items),[created['id']],'并发后的沙箱集合')
    approvals = c.all('/approvals',role='M',query={'kind':'SANDBOX_CREATE','keyword':base['name']})
    equal(snapshot_ids(approvals,'approvalId'),[created['approvalId']],'并发后的审批集合')


@case('TC-12-08', layer='业务', writes=True, needs='sandbox_body')
def sandbox_replay(c):
    body,key = c.fixture('sandbox_body'),unique()
    first = sbx_create(c,body,key)
    again = sbx_create(c,body,key)
    equal(again,first,'重放的首次业务结果')
    equal(snapshot_ids(c.all('/sandboxes',query={'projectId':body['projectId']})),[first['id']],'沙箱数量')
    approvals = c.all('/approvals',role='M',query={'kind':'SANDBOX_CREATE','keyword':body['name']})
    equal(snapshot_ids(approvals,'approvalId'),[first['approvalId']],'审批数量')


def env_path(sid,eid):
    return sandbox_path(sid)+'/environments/'+s(eid)+'/actions'


def env_status(c,sid,eid,role='A'):
    return row(status(c,sid,role)['environments'],'id',eid)


def env_action(c,sid,eid,action):
    return c.send('POST',env_path(sid,eid),body={'action':action})


def settled_env(c,sid,eid,expected):
    return c.poll(lambda:env_status(c,sid,eid),lambda x:x['status']==expected,'环境 '+expected)


@case('TC-13-01', layer='业务', writes=True, needs='environment_transitions', remainder='轮询可能跳过 STARTING/STOPPING。需观察中间态时使用控速或服务端事件。')
def start_stop(c):
    for fixture,action,before,after in zip(c.many('environment_transitions',2),
                                          ('START','STOP'),('STOPPED','RUNNING'),('RUNNING','STOPPED')):
        sid,eid = fixture['sandboxId'],fixture['environmentId']
        equal(env_status(c,sid,eid)['status'],before,'环境初始状态')
        sent = env_action(c,sid,eid,action)
        try:
            equal(environment(sent.success())['id'],eid,'操作目标环境')
            settled_env(c,sid,eid,after)
        finally:
            if sent.status==200:
                settled_env(c,sid,eid,after)
                env_action(c,sid,eid,'STOP' if action=='START' else 'START').success()
                settled_env(c,sid,eid,before)


@case('TC-13-02', layer='业务', writes=True, needs='sandbox_pending environment_pending', remainder='检查前端按钮与下游操作流水，确认无新增启停。')
def cannot_operate_pending(c):
    sid,eid = c.fixture('sandbox_pending'),c.fixture('environment_pending')
    original = env_status(c,sid,eid)
    for action in ('START','STOP'):
        env_action(c,sid,eid,action).error((400,403,409,422))
        subset(env_status(c,sid,eid),{'status':original['status'],'operationId':original.get('operationId')}
               if 'operationId' in original else {'status':original['status']})


@case('TC-13-03', writes=True, needs='sandbox_owned environment_stopped')
def environment_bad_action(c):
    sid,eid = c.fixture('sandbox_owned'),c.fixture('environment_stopped')
    original = env_status(c,sid,eid)['status']
    env_action(c,sid,eid,'RESTART').error(400)
    env_action(c,sid,unique(),'START').error(404,'ENVIRONMENT_NOT_FOUND')
    equal(env_status(c,sid,eid)['status'],original,'环境状态')


@case('TC-13-04', layer='业务', writes=True, needs='sandbox_owned sandbox_other environment_other')
def foreign_environment(c):
    sid,hidden,eid = [c.fixture(k) for k in ('sandbox_owned','sandbox_other','environment_other')]
    before = env_status(c,hidden,eid,'OTHER')
    env_action(c,sid,eid,'START').error((400,403,404,409,422))
    after = env_status(c,hidden,eid,'OTHER')
    equal((after['status'],after.get('operationId')),(before['status'],before.get('operationId')),'其他沙箱环境')


@case('TC-14-01', layer='业务', needs='sandbox_owned member_expected_ids')
def member_listing(c):
    items = members(c,c.fixture('sandbox_owned'))
    equal(snapshot_ids(items),sorted(c.fixture('member_expected_ids')),'成员集合')
    roles = set()
    for item in items:
        for k in ('id','displayName','organization'):
            field(item,k,str)
        roles.add(enum(item,'role',{'OWNER','EDITOR','VIEWER'}))
        utc(item,'joinedAt')
    equal(roles,{'OWNER','EDITOR','VIEWER'},'成员角色集合')
    equal(sum(x['role']=='OWNER' for x in items),1,'OWNER 数量')
    forbid_fields(items,PRIVATE,'成员列表')


@case('TC-15-01', layer='业务', writes=True, needs='sandbox_owned member_inputs')
def submit_member(c):
    sid = c.fixture('sandbox_owned')
    for body,role in zip(c.many('member_inputs',2),('EDITOR','VIEWER')):
        result = member_create(c,sid,{**body,'role':role})
        subset(row(member_requests(c,sid),'approvalId',result['approvalId']),{'displayName':body['displayName'],'role':role})
        approvals = c.all('/approvals',role='M',query={'kind':'MEMBER_ADD','status':'PENDING'})
        subset(row(approvals,'approvalId',result['approvalId']),{'targetId':sid})
        absent(members(c,sid),'displayName',body['displayName'])


@case('TC-15-02', writes=True, needs='sandbox_owned member_inputs')
def member_boundaries(c):
    sid = c.fixture('sandbox_owned')
    variants = [('displayName','测'*20,True),('displayName','测'*21,False),
                ('organization','测'*50,True),('organization','测'*51,False),
                ('reason','测'*9,False),('reason','测'*10,True),('reason','测'*200,True),
                ('reason','测'*201,False),('role','OWNER',False)]
    for entry,(k,v,ok) in zip(c.many('member_inputs',len(variants)),variants):
        body = {**entry,k:v}
        if ok:
            member_create(c,sid,body)
        else:
            before = snapshot_ids(member_requests(c,sid),'approvalId')
            c.send('POST',sandbox_path(sid)+'/member-requests',body=body,key=unique()).error(400)
            equal(snapshot_ids(member_requests(c,sid),'approvalId'),before,'成员申请列表')
        absent(members(c,sid),'displayName',body['displayName'])


@case('TC-15-03', layer='业务', writes=True, needs='sandbox_owned member_body')
def member_replay(c):
    sid,body = c.fixture('sandbox_owned'),c.fixture('member_body')
    key = unique()
    first = member_create(c,sid,body,key)
    equal(member_create(c,sid,body,key)['approvalId'],first['approvalId'],'同键审批 ID')
    c.send('POST',sandbox_path(sid)+'/member-requests',body=body,key=unique()).error(409,'REQUEST_DUPLICATED')
    selected = [x for x in member_requests(c,sid) if x.get('displayName')==body['displayName'] and x.get('status')=='PENDING']
    equal(snapshot_ids(selected,'approvalId'),[first['approvalId']],'待审重复申请')


@case('TC-16-01', needs='sandbox_owned member_request_samples member_request_elsewhere')
def member_history(c):
    sid = c.fixture('sandbox_owned')
    items = member_requests(c,sid)
    for item in items:
        subset(item,{'sandboxId':sid})
        for k in ('approvalId','sandboxName','applicantName','displayName','organization','role','status'):
            field(item,k,str)
        field(item,'version',int)
    for expected in c.fixture('member_request_samples'):
        subset(row(items,'approvalId',expected['approvalId']),expected,'加人记录')
    absent(items,'approvalId',c.fixture('member_request_elsewhere'))


def delete_member(c, sid, mid, role):
    return c.send('DELETE',sandbox_path(sid)+'/members/'+s(mid),role=role)


@case('TC-17-01', layer='业务', writes=True, needs='member_removal_inputs')
def remove_member(c):
    for data,role in zip(c.many('member_removal_inputs',2),('A','M')):
        sid,mid = data['sandboxId'],data['memberId']
        before = snapshot_ids(members(c,sid))
        check(mid in before,'移除夹具成员不存在')
        delete_member(c,sid,mid,role).empty_success()
        equal(snapshot_ids(members(c,sid)),[i for i in before if i!=mid],'移除后的成员')
        audit_has(c,mid,user(c.get('/me',role=role))['displayName'])


@case('TC-17-02', layer='业务', writes=True, needs='sandbox_owned member_viewer')
def editor_cannot_remove(c):
    sid,mid = c.fixture('sandbox_owned'),c.fixture('member_viewer')
    before = snapshot_ids(members(c,sid))
    check(mid in before,'VIEWER 夹具不存在')
    delete_member(c,sid,mid,'E').error(403,'FORBIDDEN')
    equal(snapshot_ids(members(c,sid)),before,'越权移除后的列表')


@case('TC-17-03', layer='业务', writes=True, needs='sandbox_owned')
def owner_protected(c):
    sid = c.fixture('sandbox_owned')
    before = members(c,sid)
    target = row(before,'role','OWNER')['id']
    for role in ('A','M'):
        delete_member(c,sid,target,role).error(400,'OWNER_PROTECTED')
        equal(row(members(c,sid),'role','OWNER')['id'],target,'原 OWNER')


@case('TC-17-04', writes=True, needs='sandbox_owned')
def missing_member(c):
    sid = c.fixture('sandbox_owned')
    before = snapshot_ids(members(c,sid))
    delete_member(c,sid,unique(),'A').error(404,'MEMBER_NOT_FOUND')
    equal(snapshot_ids(members(c,sid)),before,'成员列表')
