"""v4 and b20ab05 authentication, catalog and sandbox checks."""
from auth_sandbox import flavors, sandbox_path, user
from catalog import case
from core import Blocked, absent, check, equal, field, id_segment as s, row, snapshot_ids, subset, unique, utc


def role(c):
    return c.confirmation('sandbox_role', ('A','M')) if 'sandbox_role' in c.values else 'A'


def box(c, sid, account=None):
    data = c.get(sandbox_path(sid),role=account or role(c))
    subset(data,{'id':sid})
    field(data,'version',int)
    field(data,'environments',list)
    field(data,'allowedActions',list)
    return data


def env(obj, identity, key='id'):
    return row(field(obj,'environments',list),key,identity)


def boxes(c, **query):
    return c.all('/sandboxes',role=role(c),query=query)


def named_boxes(c, body):
    filters = {k:v for k,v in {'projectId':body.get('projectId'),'keyword':body.get('name')}.items() if v}
    return [x for x in boxes(c,**filters) if x.get('name')==body.get('name')]


def snapshot(obj):
    return (obj.get('version'),obj.get('lifecycleStatus'),
            sorted((x['id'],x.get('status'),x.get('imageId'),(x.get('flavor') or {}).get('id'))
                   for x in obj['environments']))


def target(c):
    return c.fixture('sandbox_owned')


def write(c, method, path, *, key=None, account=None, **kwargs):
    return c.send(method,path,role=account or role(c),key=key or unique(),**kwargs)


def reject(response, statuses, code=None):
    response.error(statuses,code)


def build(c, body, key=None):
    return write(c,'POST','/sandboxes',body=body,key=key)


def running(c, item):
    if c.config.get('environment')=='MOCK':
        return item.get('status') in ('SIMULATED_READY','SIMULATED') and item.get('readinessVerified') is False
    return item.get('status')=='RUNNING' and item.get('readinessVerified') is True


def is_state(c, data, expected):
    if data.get('lifecycleStatus')!=expected:
        return False
    envs=data['environments']
    if not envs:
        return False
    if expected=='ACTIVE':
        return all(running(c,item) for item in envs)
    if expected in ('STOPPED','TERMINATED'):
        return all(item.get('status')==expected or
                   expected=='TERMINATED' and item.get('status')=='DELETED' for item in envs)
    return True


def wait_state(c,sid,state):
    return c.poll(lambda:box(c,sid),lambda x:is_state(c,x,state),'沙箱 '+state)


def verify_sandbox(data, before=None):
    for k in ('id','name','projectId','lifecycleStatus'):
        field(data,k,str)
    field(data,'version',int)
    field(data,'allowedActions',list)
    if before is not None:
        equal(data['id'],before['id'],'沙箱 ID')
    return data


def power_payload(c, action, version, *, single=False):
    name = 'env_version_field' if single else 'power_version_field'
    if c.values.get(name) is None and not c.reference:
        setting = 'none'
    elif c.values.get(name) is None and single:
        setting = 'none'
    else:
        setting = c.confirmation(name, ('none','version','expectedVersion'))
    return {'action':action, **({setting:version} if setting!='none' else {})}


def power(c,sid,payload,key=None,eid=None,account=None):
    path=sandbox_path(sid)
    if eid is not None:
        path+='/environments/'+s(eid)
    return write(c,'POST',path+'/actions',body=payload,key=key,account=account)


def operation(c,operation_id,account=None):
    data=c.get(c.operation_path+'/'+s(operation_id),role=account or role(c))
    equal(field(data,'id',str),operation_id,'操作单 ID')
    return data


def op_id(data):
    return field(data,'operationId' if 'operationId' in data else 'id',str)


def wait_operation(c,identity,sid):
    def read():
        item=operation(c,identity)
        subset(item,{'sandboxId':sid})
        check(item['status']!='FAILED','已受理的操作单进入失败状态')
        return item

    return c.poll(read,lambda item:item['status'] in ('SUCCEEDED','SIMULATED'),'操作单完成')


def stop_start(c,sid,action,*,eid=None):
    before=box(c,sid)
    accepted=power(c,sid,power_payload(c,action,before['version'],single=eid is not None),eid=eid).success(status=202)
    if eid is None:
        wait_operation(c,op_id(accepted),sid)
    return accepted


@case('TC-V4-AUTH01-01', layer='业务', writes=True, needs='sandbox_owned',
      requires='SBX02 SBX05',
      remainder='如需独立确认无新增操作流水，按本轮服务端审计和运行事件复核。')
def csrf_isolation(c):
    sid=target(c)
    owner=c.client(role(c))
    owner.csrf()
    stranger_session=c.client('OTHER',fresh=True)
    foreign_token=stranger_session.csrf()
    before=box(c,sid)
    check('STOP' in before['allowedActions'],'CSRF 用例须使用允许停止的沙箱')
    payload=power_payload(c,'STOP',before['version'])
    for token in (None,'invalid-csrf-token',foreign_token):
        response=owner.request('POST',sandbox_path(sid)+'/actions',body=payload,key=unique(),csrf=token)
        reject(response,403)
        equal(snapshot(box(c,sid)),snapshot(before),'拒绝后沙箱快照')


@case('TC-V4-AUTH02-01', writes=True, requires='AUTH03', authenticated=False,
      needs='dev_login_mode', remainder='本次仅执行配置选定的启用或禁用环境，另一环境需单独执行。')
def dev_login_config(c):
    mode=c.confirmation('dev_login_mode',('enabled','disabled'))
    client=c.client(None)
    if mode=='enabled' and c.reference:
        body=c.fixture('dev_login_body')
        response=client.request('POST','/auth/dev-login',body=body)
    else:
        username,password=c.credentials('A')
        response=client.request('POST','/auth/dev-login',body={'username':username,'password':password})
    if mode=='enabled':
        response.success()
        user(client.request('GET','/me').success())
    else:
        reject(response,403)
        reject(client.request('GET','/me'),401)


@case('TC-V4-AUTH03-01', needs='account_permissions')
def session_users(c):
    reject(c.client(None).request('GET','/me'),401)
    analyst=user(c.get('/me',role='A'))
    admin=user(c.get('/me',role='M'))
    check(analyst['id']!=admin['id'],'两个独立账号返回了相同 id')
    for item,expected in ((analyst,'ANALYST'),(admin,'PLATFORM_ADMIN')):
        check(expected in item['roles'],'返回角色与测试账号不符')
    expected=c.fixture('account_permissions')
    for name,item in (('A',analyst),('M',admin)):
        equal(sorted(item['permissions']),sorted(expected[name]),'已确认的账号权限')


@case('TC-V4-AUTH04-01', requires='AUTH03', needs='logout_http')
def logout_v4(c):
    expected=c.confirmation('logout_http',(200,204))
    session=c.client()
    original=session.export_cookie()
    reply=session.request('POST','/auth/logout')
    equal(reply.status,expected,'登出响应状态')
    if expected==200:
        field(reply.body,'requestId',str)
        check('data' in reply.body,'登出信封缺 data')
    else:
        reply.empty_success()
    reject(session.request('GET','/me'),401)
    reject(c.client(None).request('GET','/me',cookie=original),401)


@case('TC-V4-AUTH05-01', authenticated=False, writes=True, requires='AUTH03',
      needs='bad_password', remainder='正式 SSO 的跳转与回调需按冻结协议在浏览器另测。')
def password_reference(c):
    if not c.reference:
        raise Blocked('v4 的 SSO 协议待确认，本脚本只支持参考包的账号密码对照')
    username,password=c.credentials('A')
    invalid=c.client(None)
    reject(invalid.request('POST','/auth/login',body={'username':username,'password':c.fixture('bad_password')}),401)
    valid=c.client(None)
    valid.request('POST','/auth/login',body={'username':username,'password':password}).success()
    user(valid.request('GET','/me').success())


@case('TC-V4-CAT01-01', needs='project_keyword project_expected_ids')
def project_filter(c):
    for page in (1,2):
        c.page('/projects',query={'page':page,'pageSize':2})
    matched=c.all('/projects',query={'keyword':c.fixture('project_keyword')})
    equal(snapshot_ids(matched),sorted(c.fixture('project_expected_ids')),'项目过滤集合')


@case('TC-V4-CAT02-01', needs='flavor_projects')
def flavor_projects(c):
    flavors(c)


@case('TC-V4-CAT02-02', needs='project_denied project_scope_http')
def flavor_rejection(c):
    outcomes=c.fixture('project_scope_http')
    for name,params in (('omitted',{}),('blank',{'projectId':''}),('denied',{'projectId':c.fixture('project_denied')})):
        check(outcomes[name] in (400,403),'目录拒绝状态配置须为 400 或 403')
        reject(c.send('GET','/resource-flavors',query=params),outcomes[name],'PROJECT_SCOPE_DENIED')


@case('TC-V4-CAT03-01', needs='image_samples')
def image_types(c):
    samples=c.fixture('image_samples')
    for kind in ('DEBUG','PRODUCTION'):
        data=c.get('/engine-images',query={'environmentType':kind})
        items=field(data,'items',list)
        subset(row(items,'id',samples[kind]['id']),samples[kind])
        check(all(item.get('environmentType')==kind for item in items),'镜像类型跨范围')
    for query in ({'environmentType':'STAGING'},{}):
        reject(c.send('GET','/engine-images',query=query),(400,403,422))


@case('TC-V4-SBX01-01', needs='sandbox_filter sandbox_filter_ids', requires='SBX02')
def sandbox_filters(c):
    query=c.fixture('sandbox_filter')
    for key in ('keyword','projectId','lifecycleStatus','flavorId'):
        c.page('/sandboxes',role=role(c),query={key:query[key],'page':1,'pageSize':2})
    matching=c.all('/sandboxes',role=role(c),query=query,page_size=2)
    equal(snapshot_ids(matching),sorted(c.fixture('sandbox_filter_ids')),'组合筛选沙箱')
    check(len(matching)>=3,'组合筛选须覆盖至少两页')
    for item in matching:
        subset(item,{k:query[k] for k in ('projectId','lifecycleStatus')})
        actual=box(c,item['id'])
        check(any((e.get('flavor') or {}).get('id')==query['flavorId'] for e in actual['environments']),
              '沙箱没有符合规格筛选的环境')
    equal(c.page('/sandboxes',role=role(c),query={**query,'keyword':unique()})['total'],0,'空结果总数')


@case('TC-V4-SBX01-03', needs='sandbox_expired sandbox_terminated',
      remainder='回收页页签、请求参数和操作按钮需用浏览器复核。')
def recycle_lists(c):
    expired,terminated=c.fixture('sandbox_expired'),c.fixture('sandbox_terminated')
    absent(boxes(c),'id',terminated)
    for status,sid in (('EXPIRED',expired),('TERMINATED',terminated)):
        items=boxes(c,lifecycleStatus=status)
        row(items,'id',sid)
        check(all(item.get('lifecycleStatus')==status for item in items),'回收状态过滤错误')


@case('TC-V4-SBX01-04', layer='业务', needs='sandbox_owned expiration_expected_environment',
      requires='SBX02', remainder='跨到期点的实时时钟和底层停机、回收事件由环境方补证。')
def expired_does_not_stop(c):
    sid=target(c)
    obj=box(c,sid)
    subset(obj,{'lifecycleStatus':'EXPIRED'})
    subset(env(obj,c.fixture('expiration_expected_environment')['id']),c.fixture('expiration_expected_environment'))
    row(boxes(c,lifecycleStatus='EXPIRED'),'id',sid)


@case('TC-V4-SBX02-01', needs='sandbox_owned')
def detail_shape(c):
    data=verify_sandbox(box(c,target(c)))
    equal(sorted(e['type'] for e in data['environments']),['DEBUG','PRODUCTION'],'沙箱双环境')
    equal(len(set(snapshot_ids(data['environments']))),2,'环境 ID 唯一性')
    for name in ('isolation','quota','expiresAt','reclaimAt'):
        check(name in data,f'详情缺少字段 {name}')
    for e in data['environments']:
        field(e,'status',str)
        field(e,'imageId',str)


@case('TC-V4-SBX02-02', layer='业务', needs='sandbox_other')
def hidden_box(c):
    target_id=c.fixture('sandbox_other')
    c.get(sandbox_path(target_id),role='OTHER')
    for sid in (target_id,unique()):
        reject(c.send('GET',sandbox_path(sid),role=role(c)),404,'NOT_FOUND')


@case('TC-V4-SBX02-03', needs='sandbox_legacy sandbox_owned legacy_detail_http',
      requires='SBX01', remainder='旧记录的页面表现与元数据迁移效果需人工复核。')
def legacy_metadata(c):
    expected=c.confirmation('legacy_detail_http',(200,404,409,422))
    box(c,target(c))
    response=c.send('GET',sandbox_path(c.fixture('sandbox_legacy')),role=role(c))
    if expected==200:
        equal(field(response.success(),'id',str),c.fixture('sandbox_legacy'),'旧沙箱详情 ID')
    else:
        reject(response,expected)
    c.page('/sandboxes',role=role(c))


@case('TC-V4-SBX02-04', needs='environment_enum_samples',
      remainder='标签展示及控速中间态需通过前端夹具或运行事件复核。')
def new_environment_enums(c):
    fixtures=c.fixture('environment_enum_samples')
    for name in ('UNPROVISIONED','CREATING','SIMULATED','DELETED','SIMULATED_READY'):
        fixture=fixtures[name]
        item=env(box(c,fixture['sandboxId']),fixture['environmentId'])
        equal(item['status'],name,'新版环境状态')
        if name=='SIMULATED_READY':
            equal(item.get('readinessVerified'),False,'MOCK 就绪标志')


@case('TC-V4-SBX03-01', needs='sandbox_owned', requires='SBX02',
      remainder='创建和启停中间态由有控速的夹具或服务端事件补证。')
def status_matches_detail(c):
    sid=target(c)
    def status():
        return c.get(sandbox_path(sid)+'/status',role=role(c))
    state=c.poll(status,lambda x:x.get('lifecycleStatus') in
                 ('ACTIVE','STOPPED','DEGRADED','FAILED','EXPIRED','TERMINATED'),'状态进入终态')
    data=box(c,sid)
    subset(state,{k:data[k] for k in ('version','allowedActions','lifecycleStatus')})
    subset(state,{'sandboxId':sid})
    equal({e['id']:e['status'] for e in state['environments']},
          {e['id']:e['status'] for e in data['environments']},'环境状态')


@case('TC-V4-SBX04-01', layer='业务', writes=True, needs='sandbox_body', requires='SBX01 SBX02',
      remainder='前端抓包与开通事件补证无审批调用及短暂过渡态。')
def create_direct(c):
    body=c.fixture('sandbox_body')
    equal(sorted(e['type'] for e in body['environments']),['DEBUG','PRODUCTION'],'创建双环境夹具')
    created=verify_sandbox(build(c,body).success(status=201))
    check(created['lifecycleStatus'] in ('PROVISIONING','ACTIVE'),'创建未直接受理开通')
    settled=wait_state(c,created['id'],'ACTIVE')
    equal(sorted(e['type'] for e in settled['environments']),['DEBUG','PRODUCTION'],'开通的环境类型')
    equal(snapshot_ids(named_boxes(c,body)),[created['id']],'新沙箱列表')


@case('TC-V4-SBX04-02', writes=True, needs='sandbox_body', requires='SBX01')
def creation_required_fields(c):
    body=c.fixture('sandbox_body')
    variants=[{k:v for k,v in body.items() if k!=field_name}
              for field_name in ('projectId','name','purpose','durationDays','environments')]
    variants.extend({**body,'authorizationScope':scope} for scope in (None,''))
    before=snapshot_ids(boxes(c,projectId=body['projectId']))
    for candidate in variants:
        reject(build(c,candidate),400,'INVALID_ARGUMENT')
        equal(snapshot_ids(boxes(c,projectId=body['projectId'])),before,'拒绝后沙箱集合')


@case('TC-V4-SBX04-03', writes=True, needs='sandbox_optional_inputs sandbox_optional_http', requires='SBX01')
def optional_fields(c):
    statuses=c.fixture('sandbox_optional_http')
    for body,name in zip(c.many('sandbox_optional_inputs',2),('dataSourceIds','authorizationScope')):
        before=snapshot_ids(named_boxes(c,body))
        response=build(c,{k:v for k,v in body.items() if k!=name})
        expected=statuses[name]
        if expected==201:
            created=verify_sandbox(response.success(status=201))
            equal(snapshot_ids(named_boxes(c,body)),sorted([*before,created['id']]),'创建写入')
        else:
            check(expected==400,'请按确认契约填 201 或 400')
            reject(response,400)
            equal(snapshot_ids(named_boxes(c,body)),before,'拒绝后沙箱集合')


@case('TC-V4-SBX04-04', layer='业务', writes=True, needs='sandbox_body', requires='SBX01',
      remainder='运行资源创建次数需通过运行方事件核对。')
def replay_create(c):
    body,key=c.fixture('sandbox_body'),unique()
    expected=200 if c.reference else c.confirmation('create_replay_http',(200,201))
    equal(named_boxes(c,body),[],'重放用例项目中的目标名称')
    first=build(c,body,key).success(status=201)
    second=build(c,body,key).success(status=expected)
    equal(field(second,'id',str),field(first,'id',str),'重放返回原沙箱 ID')
    equal(snapshot_ids(named_boxes(c,body)),[first['id']],'新增沙箱数量')


@case('TC-V4-SBX04-05', layer='业务', writes=True, needs='sandbox_body sandbox_new_name', requires='SBX01 SBX02')
def replay_create_conflict(c):
    body,key=c.fixture('sandbox_body'),unique()
    changed=c.fixture('sandbox_new_name')
    check(changed!=body['name'],'异体夹具应改变 name')
    candidate={**body,'name':changed}
    equal(named_boxes(c,candidate),[],'变更后的名称尚无沙箱')
    created=build(c,body,key).success(status=201)
    reject(build(c,candidate,key),409,'IDEMPOTENCY_CONFLICT')
    subset(box(c,created['id']),{'name':body['name']})
    equal(named_boxes(c,candidate),[],'同键异体无额外创建')


@case('TC-V4-SBX04-06', layer='业务', writes=True, needs='sandbox_mismatch_inputs', requires='SBX01',
      remainder='额外开通任务或残留资源需要后端运行事件补证。')
def sandbox_scope(c):
    for candidate in c.many('sandbox_mismatch_inputs',3):
        before=snapshot_ids(named_boxes(c,candidate))
        reject(build(c,candidate),(400,403,404,409,422))
        equal(snapshot_ids(named_boxes(c,candidate)),before,'越权或错配后无额外写入')


@case('TC-V4-SBX05-01', layer='业务', writes=True, needs='whole_power_samples', requires='SBX02 OP01')
def whole_power(c):
    for sid,action,initial,terminal,restore in zip(c.many('whole_power_samples',2),('STOP','START'),
                                                  ('ACTIVE','STOPPED'),('STOPPED','ACTIVE'),('START','STOP')):
        check(is_state(c,box(c,sid),initial),'整箱启停夹具初始状态错误')
        stop_start(c,sid,action)
        wait_state(c,sid,terminal)
        stop_start(c,sid,restore)
        wait_state(c,sid,initial)


@case('TC-V4-SBX05-03', layer='业务', writes=True, needs='sandbox_owned whole_replay_http',
      requires='SBX02 OP01', remainder='各环境的实际下游操作次数按操作流水复核。')
def whole_power_replay(c):
    expected=c.confirmation('whole_replay_http',(200,202))
    sid=target(c)
    initial=box(c,sid)
    check(is_state(c,initial,'ACTIVE'),'整箱重放夹具应先处于 ACTIVE')
    payload=power_payload(c,'STOP',initial['version'])
    key=unique()
    first=op_id(power(c,sid,payload,key).success(status=202))
    again=op_id(power(c,sid,payload,key).success(status=expected))
    equal(again,first,'重放操作单 ID')
    wait_operation(c,first,sid)
    wait_state(c,sid,'STOPPED')


@case('TC-V4-SBX05-04', layer='业务', writes=True, needs='sandbox_owned', requires='SBX02 OP01',
      remainder='用操作流水核对无第二次下游动作。')
def whole_power_conflict(c):
    sid=target(c)
    original=box(c,sid)
    key=unique()
    payload=power_payload(c,'STOP',original['version'])
    first=op_id(power(c,sid,payload,key).success(status=202))
    reject(power(c,sid,{**payload,'action':'START'},key),409,'IDEMPOTENCY_CONFLICT')
    if len(payload)>1:
        other_version=next(k for k in payload if k!='action')
        reject(power(c,sid,{**payload,other_version:original['version']+1},key),409,'IDEMPOTENCY_CONFLICT')
    wait_operation(c,first,sid)
    wait_state(c,sid,'STOPPED')


@case('TC-V4-SBX05-05', layer='业务', writes=True, needs='sandbox_owned sandbox_transition', requires='SBX02')
def reject_whole_power(c):
    sid=target(c)
    before=box(c,sid)
    stale=power_payload(c,'STOP',before['version']-1)
    if len(stale)==1:
        raise Blocked('旧版本用例须先确认 power_version_field')
    reject(power(c,sid,stale),409,'VERSION_CONFLICT')
    equal(snapshot(box(c,sid)),snapshot(before),'拒绝旧版本后沙箱')
    moving=c.fixture('sandbox_transition')
    transition=box(c,moving)
    check(transition.get('lifecycleStatus')=='PROVISIONING','过渡态夹具应保持 PROVISIONING')
    reject(power(c,moving,power_payload(c,'STOP',transition['version'])),409,'STATE_CONFLICT')


def environment_transition(c, action):
    sid=target(c)
    original=box(c,sid)
    debug=env(original,'DEBUG','type')
    production=env(original,'PRODUCTION','type')
    check(running(c,debug),'调试环境须已就绪')
    if action=='STOP':
        check(running(c,production),'生产环境须已就绪')
    else:
        equal(production['status'],'STOPPED','生产环境初始状态')
        equal(original['lifecycleStatus'],'DEGRADED','沙箱初始状态')
    stop_start(c,sid,action,eid=production['id'])
    def terminal(data):
        item=env(data,production['id'])
        return (item.get('status')=='STOPPED' and data.get('lifecycleStatus')=='DEGRADED' if action=='STOP'
                else running(c,item) and data.get('lifecycleStatus')=='ACTIVE')
    after=c.poll(lambda:box(c,sid),terminal,'单环境 '+action)
    unchanged=env(after,debug['id'])
    subset(unchanged,{k:debug[k] for k in ('status','imageId','operationId','resourceId','flavor') if k in debug})


@case('TC-V4-SBX06-01', layer='业务', writes=True, needs='sandbox_owned', requires='SBX02')
def stop_only_production(c):
    environment_transition(c,'STOP')


@case('TC-V4-SBX06-02', layer='业务', writes=True, needs='sandbox_owned', requires='SBX02',
      remainder='无调试环境下游操作事件需运行方补证。')
def start_only_production(c):
    environment_transition(c,'START')


@case('TC-V4-SBX06-03', layer='业务', writes=True, needs='sandbox_owned env_replay_http', requires='SBX02',
      remainder='通过服务端操作轨迹复核原环境实际执行次数。')
def environment_replay(c):
    expected=c.confirmation('env_replay_http',(200,202))
    sid=target(c)
    data=box(c,sid)
    debug=env(data,'DEBUG','type')
    production=env(data,'PRODUCTION','type')
    body=power_payload(c,'STOP',data['version'],single=True)
    key=unique()
    first=power(c,sid,body,key,debug['id']).success(status=202)
    repeat=power(c,sid,body,key,debug['id']).success(status=expected)
    if first.get('operationId'):
        equal(repeat.get('operationId'),first['operationId'],'原环境操作单')
    reject(power(c,sid,body,key,production['id']),409,'IDEMPOTENCY_CONFLICT')
    after=c.poll(lambda:box(c,sid),lambda data:env(data,debug['id'])['status']=='STOPPED','调试环境停止')
    subset(env(after,production['id']),{k:production[k] for k in ('status','operationId','resourceId') if k in production})


@case('TC-V4-SBX06-04', layer='业务', writes=True, needs='sandbox_owned sandbox_other environment_other',
      requires='SBX02', remainder='无额外操作记录需要审计或运行方核查。')
def environment_cross_scope(c):
    own,other,foreign=target(c),c.fixture('sandbox_other'),c.fixture('environment_other')
    before=box(c,other,'OTHER')
    env(before,foreign)
    mine=box(c,own)
    for sid,version in ((own,mine['version']),(other,before['version'])):
        payload=power_payload(c,'STOP',version,single=True)
        reject(power(c,sid,payload,eid=foreign),(403,404))
    equal(snapshot(box(c,other,'OTHER')),snapshot(before),'他人环境快照')


@case('TC-V4-SBX06-05', layer='业务', writes=True, needs='environment_transition_samples', requires='SBX02',
      remainder='无额外资源操作需要运行方补证。')
def invalid_environment_action(c):
    for sample,action in zip(c.many('environment_transition_samples',2),('TERMINATE','START')):
        sid,eid=sample['sandboxId'],sample['environmentId']
        before=box(c,sid)
        item=env(before,eid)
        if action=='START':
            equal(item['status'],'STOPPING','环境初始状态')
        else:
            check(running(c,item),'首组夹具需使用就绪环境')
        response=power(c,sid,power_payload(c,action,before['version'],single=True),eid=eid)
        if action=='START':
            reject(response,409,'STATE_CONFLICT')
        else:
            reject(response,(400,409,422))
            equal(snapshot(box(c,sid)),snapshot(before),'非法动作后快照')


def versioned(c,sid,endpoint,payload,key=None):
    return write(c,'POST',sandbox_path(sid)+endpoint,body=payload,key=key)


@case('TC-V4-SBX07-01', layer='业务', writes=True, needs='sandbox_owned environment_body', requires='SBX02',
      remainder='核对新增环境开通过程与关联操作，确认无旧审批请求。')
def add_environment(c):
    sid=target(c)
    before=box(c,sid)
    debug=env(before,'DEBUG','type')
    check(all(e['type']!='PRODUCTION' for e in before['environments']),'追加前已存在生产环境')
    payload={**c.fixture('environment_body'),'type':'PRODUCTION','version':before['version']}
    reply=versioned(c,sid,'/environments',payload).success()
    equal(field(reply,'version',int),before['version']+1,'追加版本')
    after=box(c,sid)
    production=env(after,'PRODUCTION','type')
    subset(production,{'imageId':payload['imageId']})
    subset(env(after,debug['id']),{k:debug[k] for k in ('status','imageId') if k in debug})
    equal(len(after['environments']),len(before['environments'])+1,'追加环境数量')


@case('TC-V4-SBX07-02', layer='业务', writes=True, needs='sandbox_owned environment_body duplicate_env_http', requires='SBX02')
def duplicate_environment(c):
    outcome=c.confirmation('duplicate_env_http',(200,400,409))
    sid=target(c)
    before=box(c,sid)
    payload={**c.fixture('environment_body'),'version':before['version']}
    env(before,payload['type'],'type')
    response=versioned(c,sid,'/environments',payload)
    if outcome==200:
        response.success()
    else:
        reject(response,outcome)
    equal(snapshot(box(c,sid)),snapshot(before),'重复类型没有写入')


@case('TC-V4-SBX07-03', layer='业务', writes=True, needs='sandbox_owned environment_body', requires='SBX02')
def stale_environment_version(c):
    sid=target(c)
    before=box(c,sid)
    payload={**c.fixture('environment_body'),'version':before['version']-1}
    check(all(e['type']!=payload['type'] for e in before['environments']),'旧版本用例须选择可追加类型')
    reject(versioned(c,sid,'/environments',payload),409,'VERSION_CONFLICT')
    equal(snapshot(box(c,sid)),snapshot(before),'拒绝旧版本后环境')


@case('TC-V4-SBX07-04', layer='业务', writes=True, needs='environment_concurrency_samples env_add_replay_http',
      requires='SBX02', remainder='通过下游资源和运行事件核对无重复开通。')
def environment_race(c):
    replay_http=c.confirmation('env_add_replay_http',(200,201,202))
    for sample,parallel in zip(c.many('environment_concurrency_samples',2),(False,True)):
        sid=sample['sandboxId']
        before=box(c,sid)
        body={**sample['body'],'version':before['version']}
        check(all(e['type']!=body['type'] for e in before['environments']),'夹具已存在目标环境类型')
        if parallel:
            clients=[c.client(role(c),fresh=True) for _ in range(2)]
            for client in clients:
                client.csrf()
            path=sandbox_path(sid)+'/environments'
            results=c.parallel([lambda client=client:client.request('POST',path,body=body,key=unique())
                                for client in clients])
            accepted,rejected=sorted(results,key=lambda reply:reply.status)
            accepted.success()
            reject(rejected,409)
        else:
            key=unique()
            versioned(c,sid,'/environments',body,key).success()
            versioned(c,sid,'/environments',body,key).success(status=replay_http)
        after=box(c,sid)
        env(after,body['type'],'type')
        equal(len(after['environments']),len(before['environments'])+1,'实际新增环境数')
        equal(after['version'],before['version']+1,'实际版本推进次数')


def unchanged_resource(c,sid,before):
    current=box(c,sid)
    equal(snapshot(current),snapshot(before),'资源变更前后快照')
    equal(current.get('expiresAt'),before.get('expiresAt'),'到期时间')
    equal(current.get('quota'),before.get('quota'),'配额')


@case('TC-V4-SBX08-01', layer='业务', writes=True, needs='sandbox_owned scale_body', requires='SBX02')
def independent_scale_unsupported(c):
    sid=target(c)
    before=box(c,sid)
    payload={**c.fixture('scale_body'),'version':before['version']}
    env(before,payload['environmentId'])
    reject(versioned(c,sid,'/scale',payload),501,'RESOURCE_MUTATION_UNSUPPORTED')
    unchanged_resource(c,sid,before)


@case('TC-V4-SBX08-02', layer='业务', writes=True, needs='sandbox_owned scale_variants', requires='SBX02',
      remainder='规格阶梯和实际资源分配从环境证据核对。')
def legacy_scale(c):
    sid=target(c)
    for fixture,outcome in zip(c.many('scale_variants',3),('UP','DOWN','UNKNOWN')):
        before=box(c,sid)
        body={**fixture,'version':before['version']}
        result=versioned(c,sid,'/scale',body)
        if outcome=='UP':
            result.success()
            after=box(c,sid)
            item=env(after,body['environmentId']) if body.get('environmentId') else after
            equal((item.get('flavor') or {}).get('id') or item.get('flavorId'),body['flavorId'],'升级目标规格')
            equal(after.get('expiresAt'),before.get('expiresAt'),'扩容到期时间')
            if body.get('environmentId'):
                for e in before['environments']:
                    if e['id']!=body['environmentId']:
                        equal(env(after,e['id']).get('flavor'),e.get('flavor'),'非目标环境规格')
        else:
            if outcome=='UNKNOWN':
                reject(result,400,'RESOURCE_NOT_AVAILABLE')
            else:
                reject(result,(400,409,422))
            unchanged_resource(c,sid,before)


@case('TC-V4-SBX08-03', layer='业务', writes=True, needs='sandbox_owned scale_body', requires='SBX02')
def scale_stale(c):
    sid=target(c)
    before=box(c,sid)
    reject(versioned(c,sid,'/scale',{**c.fixture('scale_body'),'version':before['version']-1}),
           409,'VERSION_CONFLICT')
    unchanged_resource(c,sid,before)


def extend(c,sid,version,days=7,key=None):
    return versioned(c,sid,'/renew',{'version':version,'durationDays':days},key)


def verify_expiry(c,before,after):
    start=utc(before,'expiresAt')
    end=utc(after,'expiresAt')
    check(end>start,'续期到期日没有顺延')
    expected=c.values.get('renew_expected_expires_at')
    if expected:
        equal(end,utc({'expiresAt':expected},'expiresAt'),'已确认计算口径的到期时间')
    equal(after['version'],before['version']+1,'续期版本')


@case('TC-V4-SBX09-01', layer='业务', writes=True, needs='sandbox_owned renew_expected_expires_at', requires='SBX02')
def renew_active(c):
    sid=target(c)
    before=box(c,sid)
    equal(before['lifecycleStatus'],'ACTIVE','续期夹具须未到期且 ACTIVE')
    extend(c,sid,before['version']).success()
    after=box(c,sid)
    verify_expiry(c,before,after)
    equal(snapshot(after)[1:],snapshot(before)[1:],'未到期续期的环境与状态')


@case('TC-V4-SBX09-02', layer='业务', writes=True, needs='sandbox_owned renewal_policy', requires='SBX02',
      remainder='是否经历 PROVISIONING 由联调运行事件复核。')
def renew_expired(c):
    policy=c.confirmation('renewal_policy',('expiry-only','restart'))
    sid=target(c)
    before=box(c,sid)
    equal(before['lifecycleStatus'],'EXPIRED','续期前到期状态')
    check(before['environments'] and all(e['status']=='STOPPED' for e in before['environments']),'续期前环境未停止')
    extend(c,sid,before['version']).success()
    after=wait_state(c,sid,'ACTIVE') if policy=='restart' else box(c,sid)
    verify_expiry(c,before,after)
    if policy=='expiry-only':
        equal(snapshot(after)[2],snapshot(before)[2],'仅延长期限时的环境快照')


@case('TC-V4-SBX09-03', layer='业务', writes=True, needs='sandbox_owned renew_replay_http', requires='SBX02')
def renew_replay(c):
    expected=c.confirmation('renew_replay_http',(200,201,202))
    sid=target(c)
    before=box(c,sid)
    key=unique()
    extend(c,sid,before['version'],key=key).success()
    once=box(c,sid)
    verify_expiry(c,before,once)
    repeat=extend(c,sid,before['version'],key=key).success(status=expected)
    equal(field(repeat,'id',str),sid,'续期重放沙箱')
    subset(box(c,sid),{'version':once['version'],'expiresAt':once['expiresAt']})


@case('TC-V4-SBX09-04', layer='业务', writes=True, needs='sandbox_owned invalid_renewal_http', requires='SBX02')
def renew_invalid(c):
    invalid=c.confirmation('invalid_renewal_http',(400,409,422))
    sid=target(c)
    before=box(c,sid)
    reject(extend(c,sid,before['version']-1),409,'VERSION_CONFLICT')
    for days in (0,-1,1.5):
        reject(extend(c,sid,before['version'],days),invalid)
        subset(box(c,sid),{'version':before['version'],'expiresAt':before['expiresAt']})


def remove_box(c,sid,version,key=None,account=None):
    return write(c,'DELETE',sandbox_path(sid),query={'version':version},key=key,account=account)


def terminate_status(c):
    return 202 if c.reference else c.confirmation('terminate_http',(200,202))


def verify_terminated(c,sid):
    wait_state(c,sid,'TERMINATED')
    absent(boxes(c),'id',sid)
    row(boxes(c,lifecycleStatus='TERMINATED'),'id',sid)


@case('TC-V4-SBX05-06', layer='业务', writes=True, needs='sandbox_termination_samples',
      requires='SBX01 SBX02 SBX10 OP01',
      remainder='前端实际入口与两个沙箱的资源无残留须另行核对。')
def termination_routes(c):
    expected=terminate_status(c)
    first,second=c.many('sandbox_termination_samples',2)
    check(first!=second,'两种注销方式使用不同沙箱')
    before=box(c,first)
    other=box(c,second)
    check(all('TERMINATE' in box_data['allowedActions'] for box_data in (before,other)),
          '两条沙箱均须允许注销')
    accepted=power(c,first,power_payload(c,'TERMINATE',before['version'])).success(status=202)
    wait_operation(c,op_id(accepted),first)
    verify_terminated(c,first)
    remove_box(c,second,other['version']).success(status=expected)
    verify_terminated(c,second)


@case('TC-V4-SBX10-01', layer='业务', writes=True, needs='sandbox_owned', requires='SBX01 SBX02',
      remainder='运行方核对资源无残留。真实资源清理以独立证据为准。')
def terminate_box(c):
    sid=target(c)
    expected=terminate_status(c)
    before=box(c,sid)
    check('TERMINATE' in before['allowedActions'],'测试沙箱当前不可注销')
    remove_box(c,sid,before['version']).success(status=expected)
    verify_terminated(c,sid)


@case('TC-V4-SBX10-02', layer='业务', writes=True, needs='sandbox_owned', requires='SBX02',
      remainder='清理动作与资源保留需要运行组件证据。')
def terminate_old_version(c):
    sid=target(c)
    before=box(c,sid)
    reject(remove_box(c,sid,before['version']-1),409,'VERSION_CONFLICT')
    unchanged_resource(c,sid,before)


@case('TC-V4-SBX10-03', layer='业务', writes=True, needs='sandbox_owned sandbox_transition', requires='SBX02',
      remainder='状态冲突的无清理副作用通过服务端事件复核。')
def terminate_forbidden(c):
    sid,moving=target(c),c.fixture('sandbox_transition')
    original,transition=box(c,sid),box(c,moving)
    c.client('E')
    reject(remove_box(c,sid,original['version'],account='E'),403,'FORBIDDEN')
    equal(snapshot(box(c,sid)),snapshot(original),'非拥有者注销后无变化')
    reject(remove_box(c,moving,transition['version']),409,'STATE_CONFLICT')


@case('TC-V4-SBX10-04', layer='业务', writes=True, needs='sandbox_owned terminate_replay_http',
      requires='SBX01 SBX02', remainder='实际清理次数和资源释放证据需由运行方回查。')
def terminate_replay(c):
    expected=terminate_status(c)
    replay=c.confirmation('terminate_replay_http',(200,202))
    sid,key=target(c),unique()
    before=box(c,sid)
    check('TERMINATE' in before['allowedActions'],'测试沙箱当前不可注销')
    first=remove_box(c,sid,before['version'],key).success(status=expected)
    second=remove_box(c,sid,before['version'],key).success(status=replay)
    if first.get('operationId'):
        equal(second.get('operationId'),first['operationId'],'注销重放操作单')
    verify_terminated(c,sid)


@case('TC-V4-SBX10-05', layer='业务', writes=True, needs='sandbox_owned sandbox_cleanup_failure cleanup_failure_state',
      requires='SBX01 SBX02', remainder='失败注入、实际残留清单及可重试条件由环境方补证。')
def cleanup_failure(c):
    accepted=terminate_status(c)
    failure=c.fixture('cleanup_failure_state')
    if failure not in ('FAILED','DEGRADED'):
        raise Blocked('需要确认可判定的清理失败状态，过渡态由运行方结合残留证据复核')
    good=target(c)
    bad=c.fixture('sandbox_cleanup_failure')
    check(good!=bad,'故障和对照须为不同沙箱')
    before_good,before_bad=box(c,good),box(c,bad)
    remove_box(c,good,before_good['version']).success(status=accepted)
    verify_terminated(c,good)
    remove_box(c,bad,before_bad['version']).success(status=accepted)
    c.poll(lambda:box(c,bad),lambda obj:obj['lifecycleStatus']==failure,'清理失败状态')


def member_path(sid):
    return sandbox_path(sid)+'/members'


def records(c,path):
    response=c.send('GET',path,role=role(c))
    data=response.success((dict,list))
    return field(data,'items',list) if isinstance(data,dict) else data


def membership(c,sid):
    return records(c,member_path(sid))


def member_events(c,sid):
    return records(c,sandbox_path(sid)+'/member-events')


def add_member(c,sid,body,key=None):
    return write(c,'POST',member_path(sid),body=body,key=key)


def remove_member(c,sid,mid,account=None):
    return write(c,'DELETE',member_path(sid)+'/'+s(mid),account=account)


def member_effect(c,sid,before_members,before_events,member_id,*,added):
    expected=set(snapshot_ids(before_members))
    if added:
        expected.add(member_id)
    else:
        expected.remove(member_id)
    equal(snapshot_ids(membership(c,sid)),sorted(expected),'成员集合')
    after=member_events(c,sid)
    equal(len(after),len(before_events)+1,'成员事件数量')
    fields=c.values.get('member_event_target_field')
    if fields:
        prior=sum(item.get(fields)==member_id for item in before_events)
        equal(sum(item.get(fields)==member_id for item in after),prior+1,'目标成员的事件')


@case('TC-V4-SBX11-01', needs='sandbox_owned sandbox_no_members member_expected_ids')
def list_members(c):
    multi=membership(c,target(c))
    equal(snapshot_ids(multi),sorted(c.fixture('member_expected_ids')),'沙箱成员 ID')
    equal(sum(x.get('role')=='OWNER' for x in multi),1,'OWNER 唯一性')
    equal(membership(c,c.fixture('sandbox_no_members')),[],'空成员数组')


@case('TC-V4-SBX12-01', layer='业务', writes=True, needs='sandbox_owned member_inputs member_event_target_field',
      requires='SBX11 SBX14', remainder='真实页面抓包复核直接调用路径及无审批请求。')
def direct_add_member(c):
    sid=target(c)
    for entry,kind in zip(c.many('member_inputs',2),('EDITOR','VIEWER')):
        before,events=membership(c,sid),member_events(c,sid)
        body={**entry,'role':kind}
        absent(before,'displayName',body['displayName'])
        result=add_member(c,sid,body).success()
        subset(result,{k:body[k] for k in ('displayName','organization','role')})
        member_effect(c,sid,before,events,field(result,'id',str),added=True)


@case('TC-V4-SBX12-02', writes=True, needs='sandbox_owned member_body', requires='SBX11 SBX14')
def add_member_invalid(c):
    sid=target(c)
    before,events=membership(c,sid),member_events(c,sid)
    body=c.fixture('member_body')
    variants=[{k:v for k,v in body.items() if k!=name} for name in ('displayName','organization','role','reason')]
    variants.extend({**body,'role':kind} for kind in ('OWNER','UNKNOWN'))
    for candidate in variants:
        reject(add_member(c,sid,candidate),400)
        equal(snapshot_ids(membership(c,sid)),snapshot_ids(before),'非法成员请求后成员列表')
        equal(member_events(c,sid),events,'非法成员请求后事件')


@case('TC-V4-SBX12-03', layer='业务', writes=True, needs='sandbox_owned member_body member_replay_http',
      requires='SBX11 SBX14')
def member_idempotent(c):
    sid,body,key=target(c),c.fixture('member_body'),unique()
    expected=c.confirmation('member_replay_http',(200,201))
    before,events=membership(c,sid),member_events(c,sid)
    absent(before,'displayName',body['displayName'])
    first=add_member(c,sid,body,key).success()
    second=add_member(c,sid,body,key).success(status=expected)
    mid=field(first,'id',str)
    equal(field(second,'id',str),mid,'成员重放 ID')
    changed='VIEWER' if body['role']=='EDITOR' else 'EDITOR'
    reject(add_member(c,sid,{**body,'role':changed},key),409,'IDEMPOTENCY_CONFLICT')
    member_effect(c,sid,before,events,mid,added=True)
    subset(row(membership(c,sid),'id',mid),{'role':body['role']})


@case('TC-V4-SBX13-01', layer='业务', writes=True, needs='sandbox_owned member_editor member_event_target_field',
      requires='SBX11 SBX14')
def remove_regular_member(c):
    sid,mid=target(c),c.fixture('member_editor')
    before,events=membership(c,sid),member_events(c,sid)
    subset(row(before,'id',mid),{'role':'EDITOR'})
    response=remove_member(c,sid,mid)
    equal(response.status,200,'移除成员 HTTP')
    field(response.body,'requestId',str)
    check('data' in response.body,'移除成员响应缺 data')
    member_effect(c,sid,before,events,mid,added=False)


@case('TC-V4-SBX13-02', layer='业务', writes=True, needs='sandbox_owned member_viewer', requires='SBX11 SBX14')
def editor_cannot_remove_member(c):
    sid,mid=target(c),c.fixture('member_viewer')
    before,events=membership(c,sid),member_events(c,sid)
    subset(row(before,'id',mid),{'role':'VIEWER'})
    reject(remove_member(c,sid,mid,'E'),403,'FORBIDDEN')
    equal(membership(c,sid),before,'拒绝后成员列表')
    equal(member_events(c,sid),events,'拒绝后成员变更流水')


@case('TC-V4-SBX13-03', layer='业务', writes=True, needs='sandbox_owned owner_remove_http', requires='SBX11 SBX14')
def owner_member_protection(c):
    expected=c.confirmation('owner_remove_http',(400,403,409,422))
    sid=target(c)
    before,events=membership(c,sid),member_events(c,sid)
    owner=row(before,'role','OWNER')
    c.client('A')
    c.client('M')
    for actor in ('A','M'):
        reject(remove_member(c,sid,owner['id'],actor),expected)
        equal(row(membership(c,sid),'role','OWNER')['id'],owner['id'],'原拥有者')
        equal(member_events(c,sid),events,'拒绝后成员事件')


@case('TC-V4-SBX14-01', layer='业务', writes=True,
      needs='sandbox_owned member_body member_event_target_field member_event_action_field member_event_actions audit_query',
      requires='SBX11 SBX12 SBX13 SEC01')
def separated_member_audit(c):
    sid=target(c)
    target_key=c.fixture('member_event_target_field')
    action_key=c.fixture('member_event_action_field')
    actions=c.fixture('member_event_actions')
    c.client('M')
    before=membership(c,sid)
    events=member_events(c,sid)
    body=c.fixture('member_body')
    absent(before,'displayName',body['displayName'])
    mid=field(add_member(c,sid,body).success(),'id',str)
    member_effect(c,sid,before,events,mid,added=True)
    removal=remove_member(c,sid,mid)
    equal(removal.status,200,'成员移除 HTTP')
    absent(membership(c,sid),'id',mid)
    matching=[entry[action_key] for entry in member_events(c,sid) if entry.get(target_key)==mid]
    equal(matching,actions,'添加与移除的事件顺序')
    absent(c.all('/audit-logs',role='M',query=c.fixture('audit_query')),'targetId',mid)


@case('TC-V4-OP01-01', needs='operation_sample', remainder='单次运行核对当前配置路径。另一部署需单独运行。')
def operation_route(c):
    sample=c.fixture('operation_sample')
    subset(operation(c,sample['id']),sample,'操作单与目标')


@case('TC-V4-OP01-02', layer='业务', writes=True, needs='sandbox_owned partial_operation_sample',
      requires='SBX02 SBX05', remainder='核对失败子环境的注入及运行侧故障记录。')
def partial_operation(c):
    sample=c.fixture('partial_operation_sample')
    sid=target(c)
    before=box(c,sid)
    reply=power(c,sid,power_payload(c,'STOP',before['version'])).success(status=202)
    operation_id=op_id(reply)
    expected=sample['status']
    check(expected not in ('SUCCEEDED','SIMULATED'),'部分失败不能配置为全部成功')
    parent=c.poll(lambda:operation(c,operation_id),lambda x:x.get('status')==expected,'部分失败的父操作')
    results=field(parent,sample['childrenField'],list)
    for child in sample['children']:
        subset(row(results,'environmentId',child['environmentId']),child)
    detail=box(c,sid)
    for state in sample['environments']:
        subset(env(detail,state['id']),state)


@case('TC-V4-OP01-03', layer='业务', needs='operation_other')
def operation_not_visible(c):
    target_id=c.fixture('operation_other')
    operation(c,target_id,'OTHER')
    for operation_id in (target_id,unique()):
        reject(c.send('GET',c.operation_path+'/'+s(operation_id),role=role(c)),(403,404))
