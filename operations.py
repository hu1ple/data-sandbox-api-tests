"""Read-only tasks, security, integrations, settings and operations."""
from catalog import case
from core import check, enum, equal, field, forbid_fields, id_segment as s, row, snapshot_ids, subset, unique, utc, settings
from auth_sandbox import PRIVATE, audit_has, user


def pages(c, path, filters, role='A'):
    first = c.page(path,role=role,query={**filters,'page':1,'pageSize':1})
    second = c.page(path,role=role,query={**filters,'page':2,'pageSize':1})
    equal(first['total'],second['total'],'两页总数')
    check(not set(snapshot_ids(first['items'])) & set(snapshot_ids(second['items'])),'跨页记录重复')
    return first['items']+second['items']


def task(item):
    for k in ('id','sandboxId','sandboxName','name','ownerId','ownerName'):
        field(item,k,str)
    enum(item,'type',{'SQL','NOTEBOOK','JOB'})
    enum(item,'status',{'QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELED'})
    utc(item,'startedAt')
    utc(item,'finishedAt',nullable=True)
    field(item,'durationSec',(int,float),nullable=True)
    return item


@case('TC-18-01', needs='sandbox_owned task_keyword task_expected_ids')
def task_listing(c):
    filters = {'sandboxId':c.fixture('sandbox_owned'),'status':'RUNNING','keyword':c.fixture('task_keyword')}
    pages(c,'/tasks',filters)
    items = c.all('/tasks',query=filters)
    equal(snapshot_ids(items),sorted(c.fixture('task_expected_ids')),'任务结果集合')
    for item in items:
        task(item)
        subset(item,{'sandboxId':filters['sandboxId'],'status':'RUNNING','finishedAt':None,'durationSec':None})


@case('TC-19-01', needs='task_detail_samples')
def task_detail(c):
    for sample in c.many('task_detail_samples',2):
        data = task(c.get('/tasks/'+s(sample['id'])))
        subset(data,sample,'任务及预置日志顺序')
        check(all(isinstance(x,str) for x in field(data,'logs',list)),'日志不是逐行字符串')
        items = c.all('/tasks',query={'sandboxId':data['sandboxId'],'keyword':data['name']})
        listed = row(items,'id',data['id'])
        for key,value in listed.items():
            if key!='logs':
                subset(data,{key:value},'列表和详情')


@case('TC-19-02')
def missing_task(c):
    c.send('GET','/tasks/'+s(unique())).error(404,'TASK_NOT_FOUND')


@case('TC-20-01', needs='audit_filter audit_expected_ids')
def audit_filter(c):
    for result in ('SUCCESS','DENIED'):
        query = {'keyword':c.fixture('audit_filter'),'result':result}
        c.page('/audit-logs',role='M',query={**query,'page':1,'pageSize':2})
        items = c.all('/audit-logs',role='M',query=query)
        equal(snapshot_ids(items),sorted(c.fixture('audit_expected_ids')[result]),'审计筛选集合')
        for x in items:
            for k in ('id','actorName','action','targetType','targetId','ip'):
                field(x,k,str)
            utc(x,'at')
            equal(x.get('result'),result,'审计结果')
        forbid_fields(items,PRIVATE,'审计列表')


@case('TC-20-02', layer='业务', remainder='用真实前端核对分析员安全菜单隐藏。')
def no_audit_access(c):
    for path in ('/audit-logs','/violations'):
        c.send('GET',path,query={'page':1,'pageSize':20}).error(403)


@case('TC-20-03', layer='业务', needs='audit_targets',
      remainder='先执行或由联调方触发七种真实操作并记录其目标、操作人、action，再用本脚本回查审计。')
def seven_audits(c):
    samples = c.fixture('audit_targets')
    equal(set(samples),{'A07','A09','A13','A14','A16','A17','A18'},'需要回查的七项审计')
    for details in samples.values():
        audit_has(c,details['targetId'],details['actorName'],details['action'])


@case('TC-21-01', needs='violation_high_open_ids violation_empty_filters')
def violations(c):
    filters = {'severity':'HIGH','status':'OPEN'}
    pages(c,'/violations',filters,'M')
    items = c.all('/violations',role='M',query=filters)
    equal(snapshot_ids(items),sorted(c.fixture('violation_high_open_ids')),'违规筛选集合')
    for item in items:
        subset(item,filters)
        utc(item,'at')
        for key in ('sandboxName','type','detail'):
            field(item,key,str)
    empty = c.page('/violations',role='M',query=c.fixture('violation_empty_filters'))
    equal((empty['items'],empty['total']),([],0),'空违规分页')


def violation(c,target,status):
    return row(c.all('/violations',role='M',query={'status':status}),'id',target)


@case('TC-22-01', layer='业务', writes=True, needs='violation_open')
def handle_violation(c):
    target = c.fixture('violation_open')
    violation(c,target,'OPEN')
    actor = user(c.get('/me',role='M'))['displayName']
    expected = {'id':target,'status':'HANDLED','handler':actor}
    subset(c.send('POST','/violations/'+s(target)+'/handle',role='M').success(),expected)
    subset(violation(c,target,'HANDLED'),expected)
    audit_has(c,target,actor)


@case('TC-22-02', layer='业务', writes=True, needs='violation_open')
def invalid_violation(c):
    target = c.fixture('violation_open')
    before = violation(c,target,'OPEN')
    c.send('POST','/violations/'+s(unique())+'/handle',role='M').error(404,'VIOLATION_NOT_FOUND')
    c.send('POST','/violations/'+s(target)+'/handle').error(403)
    equal(violation(c,target,'OPEN'),before,'原违规记录')


@case('TC-23-01', needs='integration_samples')
def integration_directory(c):
    items = field(c.get('/integrations',role='M'),'items',list)
    equal(sorted(field(x,'code',str) for x in items),sorted(f'D{i}' for i in range(1,11)),'D1–D10')
    for item in items:
        for k in ('name','description','owner'):
            field(item,k,str)
        enum(item,'status',{'CONNECTED','DISCONNECTED','DEGRADED'})
        utc(item,'lastSyncAt',nullable=True)
    for sample in c.fixture('integration_samples'):
        subset(row(items,'code',sample['code']),sample,'对接状态')


@case('TC-24-01', needs='exception_samples')
def exceptions(c):
    for stage in ('OPEN','RESOLVED'):
        data = c.page('/integrations/exceptions',role='M',query={'status':stage,'pageSize':1})
        check(data['total']>=1,'缺少该状态样本')
        items = c.all('/integrations/exceptions',role='M',query={'status':stage})
        for item in items:
            subset(item,{'status':stage})
            field(item,'retryable',bool)
            for k in ('id','integrationCode','integrationName','code','message'):
                field(item,k,str)
            utc(item,'at')
        for sample in c.fixture('exception_samples')[stage]:
            subset(row(items,'id',sample['id']),sample,'对接异常')


def exception(c,target,stage='OPEN'):
    return row(c.all('/integrations/exceptions',role='M',query={'status':stage}),'id',target)


@case('TC-25-01', layer='业务', writes=True, needs='exception_retryable')
def retry_exception(c):
    target = c.fixture('exception_retryable')
    equal(exception(c,target)['retryable'],True,'对接异常重试资格')
    changed = {'id':target,'status':'RESOLVED'}
    subset(c.send('POST','/integrations/exceptions/'+s(target)+'/retry',role='M').success(),changed)
    subset(exception(c,target,'RESOLVED'),changed)
    audit_has(c,target,user(c.get('/me',role='M'))['displayName'])


@case('TC-25-02', layer='业务', writes=True, needs='exception_not_retryable')
def exception_rejection(c):
    target = c.fixture('exception_not_retryable')
    before = exception(c,target)
    equal(before['retryable'],False,'对接异常重试资格')
    c.send('POST','/integrations/exceptions/'+s(target)+'/retry',role='M').error(400,'NOT_RETRYABLE')
    c.send('POST','/integrations/exceptions/'+s(unique())+'/retry',role='M').error(404,'EXCEPTION_NOT_FOUND')
    equal(exception(c,target),before,'原异常状态')


@case('TC-25-03', layer='业务', writes=True, needs='exception_retryable')
def no_integration_access(c):
    target = c.fixture('exception_retryable')
    before = exception(c,target)
    for path in ('/integrations','/integrations/exceptions'):
        c.send('GET',path).error(403)
    c.send('POST','/integrations/exceptions/'+s(target)+'/retry').error(403)
    equal(exception(c,target),before,'越权后的异常状态')


@case('TC-26-01', needs='settings_expected')
def settings_permissions(c):
    subset(settings(c.get('/settings',role='M')),c.fixture('settings_expected'))
    c.send('GET','/settings').error(403)


def put_settings(c,body):
    reply = settings(c.send('PUT','/settings',role='M',body=body).success())
    subset(reply,body,'配置回显')
    subset(settings(c.get('/settings',role='M')),body,'配置回读')
    return reply


@case('TC-27-01', layer='业务', writes=True, needs='settings_body settings_audit_target')
def save_settings(c):
    with c.saved_settings() as before:
        payload = c.fixture('settings_body')
        check(all(payload[k]!=v for k,v in before.items()),'四项配置的测试值应与基线不同')
        original = utc(c.get('/settings',role='M'),'updatedAt')
        written = put_settings(c,payload)
        check(utc(written,'updatedAt')>=original,'配置时间倒退')
        reader = c.client('M',fresh=True)
        subset(reader.request('GET','/settings').success(),payload,'新会话配置')
        audit_has(c,c.fixture('settings_audit_target'),user(c.get('/me',role='M'))['displayName'])


@case('TC-27-02', writes=True)
def settings_bounds(c):
    with c.saved_settings() as before:
        for value in (0,1,3650,3651,1.5):
            payload = {**before,'retentionDays':value}
            if value in (1,3650):
                put_settings(c,payload)
            else:
                previous = c.get('/settings',role='M')
                c.send('PUT','/settings',role='M',body=payload).error(400)
                equal(c.get('/settings',role='M'),previous,'无效保留天数后的配置')
        for key in ('exportApprovalRequired','watermarkEnabled'):
            previous = c.get('/settings',role='M')
            for invalid in ({**before,key:'false'},{k:v for k,v in before.items() if k!=key}):
                c.send('PUT','/settings',role='M',body=invalid).error(400)
                equal(c.get('/settings',role='M'),previous,'无效开关后的配置')


@case('TC-27-03', writes=True, remainder='用实际新建页核对默认期限是否跟随配置，见 G-01。')
def common_default_days(c):
    with c.saved_settings() as before:
        for value in (7,90,0,366,7.5):
            payload = {**before,'defaultSandboxDays':value}
            if value in (7,90):
                put_settings(c,payload)
            else:
                previous = c.get('/settings',role='M')
                c.send('PUT','/settings',role='M',body=payload).error(400)
                equal(c.get('/settings',role='M'),previous,'拒绝后的配置')


@case('TC-27-05', layer='业务', writes=True)
def unauthorized_settings(c):
    with c.saved_settings() as baseline:
        before = c.get('/settings',role='M')
        value = 45 if baseline['defaultSandboxDays']!=45 else 46
        c.send('PUT','/settings',body={**baseline,'defaultSandboxDays':value}).error(403)
        equal(c.get('/settings',role='M'),before,'越权后的平台配置')


@case('TC-28-01', needs='operation_samples', remainder='失败夹具需由环境方注入可核对的错误，并与环境详情比对。')
def operation_detail(c):
    for fixture in c.many('operation_samples',2):
        target = fixture['id']
        path = '/operations/'+s(target)
        item = c.poll(lambda:c.get(path),lambda x:x.get('status') in ('SUCCEEDED','FAILED','SIMULATED'),'操作终态')
        subset(item,fixture,'操作详情')
        for key in ('id','sandboxId','type','status','phase','runtimeMode'):
            field(item,key,str)
        utc(item,'updatedAt')
        enum(item,'runtimeMode',{'REAL','MOCK'})
        if item['status']=='FAILED':
            for key in ('failureCode','failureMessage'):
                field(item,key,str)
