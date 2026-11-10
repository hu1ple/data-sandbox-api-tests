"""Approval decisions and transitions across projects, sandboxes and members."""
from catalog import case
from core import absent, check, enum, equal, field, id_segment as s, row, snapshot_ids, subset, unique, utc
from auth_sandbox import (
    audit_has, delete_member, env_action, env_status, member_create, member_requests, members,
    sandbox, sandbox_path, sbx_create, settled_env, status, user,
)

KINDS = {'DATA_REQUEST','SANDBOX_CREATE','MEMBER_ADD'}


def approval_rows(c, **filters):
    return c.all('/approvals',role='M',query=filters)


def approval(c, aid, **filters):
    return row(approval_rows(c,**filters),'approvalId',aid)


def approval_shape(data):
    for k in ('approvalId','title','applicantId','applicantName','summary','detail','targetId'):
        field(data,k,str)
    enum(data,'kind',KINDS)
    enum(data,'status',{'PENDING','APPROVED','REJECTED'})
    field(data,'version',int)
    utc(data,'createdAt')
    if data.get('decidedAt'):
        utc(data,'decidedAt')
    return data


def approval_path(aid):
    return '/approvals/'+s(aid)+'/decisions'


def decision_body(version, action='APPROVE', comment='同意测试申请'):
    return {'decision':action,'comment':comment,'expectedVersion':version}


def decide(c, aid, payload, *, role='M', key=None):
    return c.send('POST',approval_path(aid),role=role,body=payload,key=key or unique())


def changed(c, original, action, comment):
    aid = original['approvalId']
    outcome = 'APPROVED' if action=='APPROVE' else 'REJECTED'
    result = decide(c,aid,decision_body(original['version'],action,comment)).success()
    subset(result,{'approvalId':aid,'status':outcome},'审批结果')
    check(field(result,'version',int)>original['version'],'审批版本未前进')
    utc(result,'updatedAt')
    historical = approval(c,aid,kind=original['kind'],status=outcome)
    subset(historical,{'version':result['version'],'comment':comment},'审批历史')
    utc(historical,'decidedAt')
    return result


def data_submit(c, body, key=None):
    data = c.send('POST','/data-requests',body=body,key=key or unique()).success()
    field(data,'approvalId',str)
    equal(field(data,'approvalStatus',str),'PENDING','入库审批状态')
    check(data.get('projectId') is None,'待审入库申请已生成项目')
    utc(data,'updatedAt')
    return data


def projects(c, name):
    return [item for item in c.all('/projects',query={'keyword':name}) if item.get('name')==name]


def pending_data(c):
    body = c.fixture('data_body')
    project = body['projectName'].strip()
    equal(projects(c,project),[],'新项目的初始记录')
    result = data_submit(c,body)
    entry = approval(c,result['approvalId'],kind='DATA_REQUEST',status='PENDING',keyword=project)
    equal(entry['title'],project,'入库申请项目名')
    return entry, project


@case('TC-29-01', needs='approval_samples')
def aggregate_approvals(c):
    entries = c.fixture('approval_samples')
    equal(set(entries),KINDS,'审批夹具类型')
    items = approval_rows(c,status='PENDING')
    for kind,sample in entries.items():
        data = approval_shape(row(items,'approvalId',sample['approvalId']))
        subset(data,sample,'预置审批')
        subset(data,{'kind':kind,'status':'PENDING'})
        if kind=='DATA_REQUEST':
            equal(data['targetId'],data['approvalId'],'入库审批 targetId')


@case('TC-29-02', needs='approval_filter_keyword approval_expected_ids')
def filter_approvals(c):
    query = {'kind':'MEMBER_ADD','status':'APPROVED','keyword':c.fixture('approval_filter_keyword')}
    first = c.page('/approvals',role='M',query={**query,'page':1,'pageSize':1})
    second = c.page('/approvals',role='M',query={**query,'page':2,'pageSize':1})
    check(not set(snapshot_ids(first['items'],'approvalId')) & set(snapshot_ids(second['items'],'approvalId')),'审批分页有重复')
    items = approval_rows(c,**query)
    equal(snapshot_ids(items,'approvalId'),sorted(c.fixture('approval_expected_ids')),'审批筛选')
    for item in items:
        approval_shape(item)
        subset(item,{'kind':'MEMBER_ADD','status':'APPROVED'})
        utc(item,'decidedAt')
        check(isinstance(item.get('comment'),str),'已决定审批缺少意见')
    equal(c.page('/approvals',role='M',query={**query,'keyword':unique()})['total'],0,'无匹配审批')


@case('TC-29-03', layer='业务', writes=True, needs='approval_pending',
      remainder='如需独立核对下游事件，联调方按实际审批 kind 回查对应业务对象。')
def unauthorized_approval(c):
    aid = c.fixture('approval_pending')
    before = approval(c,aid,status='PENDING')
    c.send('GET','/approvals').error(403)
    decide(c,aid,decision_body(before['version']),role='A').error(403)
    equal(approval(c,aid,status='PENDING'),before,'无权限审批后状态')


@case('TC-30-01', layer='业务', writes=True, needs='data_body')
def approve_data(c):
    entry,name = pending_data(c)
    changed(c,entry,'APPROVE','同意入库')
    target = row(projects(c,name),'name',name)
    field(target,'id',str)


@case('TC-30-02', layer='业务', writes=True, needs='data_body')
def reject_data(c):
    entry,name = pending_data(c)
    changed(c,entry,'REJECT','来源口径需补充')
    equal(projects(c,name),[],'驳回后的项目')


def approve_sandbox(c, original):
    sid, aid = original['id'], original['approvalId']
    entry = approval(c,aid,kind='SANDBOX_CREATE',status='PENDING')
    result = changed(c,entry,'APPROVE','同意建箱')
    stable = c.poll(lambda:status(c,sid),lambda x:x['lifecycleStatus']=='ACTIVE','沙箱 ACTIVE')
    check(bool(stable['environments']),'已放行沙箱没有环境')
    detail = sandbox(c.get(sandbox_path(sid)))
    subset(detail,{'lifecycleStatus':'ACTIVE','approvalStatus':'APPROVED'})
    utc(detail,'expiresAt')
    if result.get('operationId'):
        operation = c.get('/operations/'+s(result['operationId']))
        subset(operation,{'id':result['operationId'],'sandboxId':sid},'沙箱开通操作')
    absent(c.all('/projects'), 'id', original['projectId'])
    return detail


@case('TC-30-03', layer='业务', writes=True, needs='sandbox_body',
      remainder='中间态 PROVISIONING 与期限计算基准可用后端事件和 G-10 的确认口径复核。')
def approve_sandbox_case(c):
    body = c.fixture('sandbox_body')
    detail = approve_sandbox(c,sbx_create(c,body))
    equal(sorted(env['type'] for env in detail['environments']),
          sorted(env['type'] for env in body['environments']),'已开通环境类型')


@case('TC-30-04', layer='业务', writes=True, needs='sandbox_body')
def reject_sandbox(c):
    created = sbx_create(c,c.fixture('sandbox_body'))
    entry = approval(c,created['approvalId'],kind='SANDBOX_CREATE',status='PENDING')
    changed(c,entry,'REJECT','用途需调整')
    detail = sandbox(c.get(sandbox_path(created['id'])))
    subset(detail,{'lifecycleStatus':'REJECTED','approvalStatus':'REJECTED'})
    check(bool(detail['environments']),'测试沙箱缺环境记录')
    check(all(env['status']=='TERMINATED' for env in detail['environments']),'驳回后环境未终止')


def member_decision(c, action):
    sid, body = c.fixture('sandbox_owned'),c.fixture('member_body')
    before = members(c,sid)
    absent(before,'displayName',body['displayName'])
    request = member_create(c,sid,body)
    absent(members(c,sid),'displayName',body['displayName'])
    entry = approval(c,request['approvalId'],kind='MEMBER_ADD',status='PENDING')
    comment = '确认加入' if action=='APPROVE' else '申请理由不足'
    result = changed(c,entry,action,comment)
    subset(row(member_requests(c,sid),'approvalId',request['approvalId']),
           {'status':result['status'],'comment':comment})
    after = members(c,sid)
    if action=='REJECT':
        absent(after,'displayName',body['displayName'])
        equal(snapshot_ids(after),snapshot_ids(before),'驳回后的成员')
        return None
    member = row(after,'displayName',body['displayName'])
    subset(member,{'organization':body['organization'],'role':body['role']})
    equal(row(after,'role','OWNER')['id'],row(before,'role','OWNER')['id'],'OWNER')
    return request['approvalId'],member['id']


@case('TC-30-05', layer='业务', writes=True, needs='sandbox_owned member_body')
def approve_member(c):
    member_decision(c,'APPROVE')


@case('TC-30-06', layer='业务', writes=True, needs='sandbox_owned member_body')
def reject_member(c):
    member_decision(c,'REJECT')


@case('TC-30-07', layer='业务', writes=True, needs='data_body')
def old_version(c):
    entry,name = pending_data(c)
    aid = entry['approvalId']
    decide(c,aid,decision_body(entry['version']-1)).error(409,'VERSION_CONFLICT')
    equal(approval(c,aid,status='PENDING',keyword=name),entry,'版本冲突后的审批')
    equal(projects(c,name),[],'版本冲突后的项目')


@case('TC-30-08', layer='业务', writes=True, needs='data_body')
def decision_already_made(c):
    entry,name = pending_data(c)
    aid = entry['approvalId']
    result = changed(c,entry,'APPROVE','同意入库')
    before = approval(c,aid,status='APPROVED',keyword=name)
    original_projects = snapshot_ids(projects(c,name))
    equal(len(original_projects),1,'首次通过建立项目')
    decide(c,aid,decision_body(result['version'],'REJECT','禁止再次处理')).error(409,'APPROVAL_ALREADY_DECIDED')
    equal(approval(c,aid,status='APPROVED',keyword=name),before,'原审批决定')
    equal(snapshot_ids(projects(c,name)),original_projects,'原项目记录')


@case('TC-30-09', layer='业务', writes=True, needs='data_body',
      remainder='项目和历史做自动断言。审批成功流水计数需按部署确认审计 targetId 和 action。')
def approval_replay(c):
    entry,name = pending_data(c)
    aid = entry['approvalId']
    key,payload = unique(),decision_body(entry['version'])
    first = decide(c,aid,payload,key=key).success()
    equal(decide(c,aid,payload,key=key).success(),first,'审批重放的首次结果')
    equal(field(first,'status',str),'APPROVED','审批重放状态')
    subset(approval(c,aid,status='APPROVED',keyword=name),{'version':first['version']})
    equal(len(projects(c,name)),1,'项目副作用次数')


@case('TC-30-10', layer='业务', writes=True, needs='data_body')
def concurrent_approval(c):
    entry,name = pending_data(c)
    aid, version = entry['approvalId'],entry['version']
    clients = [c.client(role) for role in ('M','M2')]
    for client in clients:
        client.csrf()
    calls = [
        lambda client=client,action=action:client.request('POST',approval_path(aid),
            body=decision_body(version,action,'并发审批测试'),key=unique())
        for client,action in zip(clients,('APPROVE','REJECT'))
    ]
    accepted,rejected = sorted(c.parallel(calls),key=lambda item:item.status)
    result = accepted.success()
    rejected.error(409,('VERSION_CONFLICT','APPROVAL_ALREADY_DECIDED'))
    outcome = enum(result,'status',{'APPROVED','REJECTED'})
    equal(approval(c,aid,status=outcome,keyword=name)['version'],result['version'],'决定版本')
    equal(len(projects(c,name)),1 if outcome=='APPROVED' else 0,'并发审批项目写入')


@case('TC-30-11', writes=True, needs='approval_validation_ids')
def decision_validation(c):
    variants = [('comment',None),('comment',''),('comment','测'*200),
                ('comment','测'*201),('decision','RETURN'),('expectedVersion',None)]
    for aid,(key,value) in zip(c.many('approval_validation_ids',len(variants)),variants):
        previous = approval(c,aid,status='PENDING')
        body = decision_body(previous['version'],'REJECT','原因说明')
        if value is None:
            del body[key]
        else:
            body[key] = value
        response = decide(c,aid,body)
        if key=='comment' and value=='测'*200:
            subset(response.success(),{'status':'REJECTED'})
            subset(approval(c,aid,status='REJECTED'),{'comment':value})
        else:
            response.error(400)
            equal(approval(c,aid,status='PENDING'),previous,'拒绝后的审批')


@case('TC-30-12', writes=True)
def missing_approval(c):
    decide(c,unique(),decision_body(1)).error(404,'APPROVAL_NOT_FOUND')


@case('TC-30-14', layer='业务', writes=True, needs='data_body sandbox_chain_body')
def project_to_environment(c):
    entry,name = pending_data(c)
    changed(c,entry,'APPROVE','同意入库')
    project = row(projects(c,name),'name',name)
    payload = {**c.fixture('sandbox_chain_body'),'projectId':project['id']}
    detail = approve_sandbox(c,sbx_create(c,payload))
    debug = row(detail['environments'],'type','DEBUG')
    production = row(detail['environments'],'type','PRODUCTION')
    sid = detail['id']
    equal(debug['status'],'RUNNING','调试环境初始状态')
    env_action(c,sid,debug['id'],'STOP').success()
    try:
        settled_env(c,sid,debug['id'],'STOPPED')
    finally:
        env_action(c,sid,debug['id'],'START').success()
        settled_env(c,sid,debug['id'],'RUNNING')
    equal(env_status(c,sid,production['id'])['status'],production['status'],'生产环境状态')


@case('TC-30-15', layer='业务', writes=True, needs='sandbox_owned member_body')
def member_join_remove_chain(c):
    equal(c.fixture('member_body')['role'],'VIEWER','串测成员初始申请角色')
    sid = c.fixture('sandbox_owned')
    aid, mid = member_decision(c,'APPROVE')
    delete_member(c,sid,mid,'A').empty_success()
    after = members(c,sid)
    absent(after,'id',mid)
    row(after,'role','OWNER')
    audit_has(c,aid,user(c.get('/me',role='M'))['displayName'])
    audit_has(c,mid,user(c.get('/me'))['displayName'])
