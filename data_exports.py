"""Data requests, ingestions, datasets, results and export scripts."""
from catalog import case
from core import absent, check, enum, equal, field, forbid_fields, id_segment as s, row, snapshot_ids, subset, unique, utc
from approvals import approval, approval_rows, data_submit, projects

SOURCE_SECRET_KEYS = {
    'connectionstring','connectionurl','connectionuri','connstr','dsn','jdbcurl','username',
    'account','password','passwd','secret','secretkey','accesskey','credentials','token','apikey',
}
EXPORT_STATES = ('PENDING_REVIEW','REVIEW_REJECTED','PENDING_APPROVAL','APPROVED','REJECTED',
                 'DELIVERING','DELIVERED','DELIVERY_FAILED','EXPIRED')


@case('TC-31-01', needs='resource_keyword resource_samples')
def resource_directory(c):
    query = {'keyword':c.fixture('resource_keyword')}
    entries = c.fixture('resource_samples')
    pages = [c.page('/data-resources',query={**query,'page':n,'pageSize':1}) for n in (1,2)]
    check(not set(snapshot_ids(pages[0]['items'])) & set(snapshot_ids(pages[1]['items'])),'资源分页重复')
    equal(pages[0]['total'],len(entries),'目录总数')
    items = c.all('/data-resources',query=query)
    equal(snapshot_ids(items),snapshot_ids(entries),'授权资源集合')
    for expected in entries:
        data = row(items,'id',expected['id'])
        subset(data,expected)
        field(data,'name',str)
        enum(data,'authorizationStatus',{'GRANTED','REVOKED','EXPIRED'})
        utc(data,'authorizationExpiresAt',nullable=True)
        field(data,'allowedActions',list)
    data = c.page('/data-resources',query={'keyword':unique()})
    equal((data['items'],data['total']),([],0),'空资源页')


def string_values(obj):
    if isinstance(obj,str):
        yield obj
    elif isinstance(obj,list):
        for item in obj:
            yield from string_values(item)
    elif isinstance(obj,dict):
        for value in obj.values():
            yield from string_values(value)


@case('TC-32-01', layer='业务', needs='source_samples',
      remainder='浏览器复查 DISCONNECTED 可见但禁用。可用 SANDBOX_QA_SOURCE_SENTINELS（用换行分隔）核对服务端合成凭据值。')
def source_directory(c):
    from os import environ
    response = c.send('GET','/data-sources')
    items = field(response.success(),'items',list)
    samples = c.fixture('source_samples')
    equal({item['status'] for item in samples},{'CONNECTED','DEGRADED','DISCONNECTED'},'数据源状态夹具')
    for expected in samples:
        actual = row(items,'id',expected['id'])
        subset(actual,expected)
        for key in ('id','name','description'):
            field(actual,key,str)
        enum(actual,'type',{'BUSINESS_DB','DATA_WAREHOUSE','FILE_SERVER','OBJECT_STORAGE'})
    forbid_fields(response.body,SOURCE_SECRET_KEYS,'数据源目录')
    secrets = [v for v in environ.get('SANDBOX_QA_SOURCE_SENTINELS','').splitlines() if v.strip()]
    observed = list(string_values(response.body))
    for value in secrets:
        check(not any(value in text for text in observed),'数据源目录泄露测试凭据值')


def data_approval_ids(c, name):
    return snapshot_ids(approval_rows(c,kind='DATA_REQUEST',keyword=name),'approvalId')


def reject_data(c, body, code=None):
    name = body.get('projectName','').strip()
    check(bool(name) or code is None,'测试夹具缺项目名称')
    before = data_approval_ids(c,name)
    expected_projects = snapshot_ids(projects(c,name)) if name else []
    c.send('POST','/data-requests',body=body,key=unique()).error(400,code)
    equal(data_approval_ids(c,name),before,'拒绝后的入库申请')
    if name:
        equal(snapshot_ids(projects(c,name)),expected_projects,'拒绝后的项目')


@case('TC-34-01', layer='业务', writes=True, needs='data_body')
def submit_sync(c):
    body = c.fixture('data_body')
    project_name = body['projectName'].strip()
    equal(projects(c,project_name),[],'提交前项目目录')
    data = data_submit(c,{**body,'projectName':'  '+project_name+'  '})
    entry = approval(c,data['approvalId'],kind='DATA_REQUEST',status='PENDING',keyword=project_name)
    subset(entry,{'title':project_name,'targetId':data['approvalId']})
    equal(projects(c,project_name),[],'审批前项目目录')


@case('TC-34-02', layer='业务', writes=True, needs='data_body source_degraded')
def degraded_source(c):
    body = {**c.fixture('data_body'),'sourceId':c.fixture('source_degraded')}
    sources = field(c.get('/data-sources'),'items',list)
    equal(row(sources,'id',body['sourceId'])['status'],'DEGRADED','数据源状态')
    data = data_submit(c,body)
    approval(c,data['approvalId'],kind='DATA_REQUEST',status='PENDING',keyword=body['projectName'])


@case('TC-34-03', layer='业务', writes=True, needs='data_body source_disconnected')
def invalid_source(c):
    body = c.fixture('data_body')
    without = {k:v for k,v in body.items() if k!='sourceId'}
    for invalid in (without,{**body,'sourceId':unique()},{**body,'sourceId':c.fixture('source_disconnected')}):
        reject_data(c,invalid,'INVALID_SOURCE')


@case('TC-34-04', writes=True, needs='data_body')
def project_name_bounds(c):
    base = c.fixture('data_body')
    for name,accepted in [('测',False),('测'*2,True),('测'*40,True),('测'*41,False),('  ',False)]:
        body = {**base,'projectName':name}
        if accepted:
            data_submit(c,body)
        else:
            reject_data(c,body)
    reject_data(c,{**base,'accessMode':'HTTP'})


@case('TC-34-05', writes=True, needs='data_inputs')
def data_description_bounds(c):
    variants = [(key,value) for key in ('dataSource','purpose') for value in (None,'','测'*10,'测'*500,'测'*501)]
    for body,(key,value) in zip(c.many('data_inputs',len(variants)),variants):
        if value is None:
            body.pop(key,None)
        else:
            body[key] = value
        if value in ('测'*10,'测'*500):
            data_submit(c,body)
        else:
            reject_data(c,body)


@case('TC-34-07', layer='业务', writes=True, needs='data_body')
def data_replay(c):
    body,key = c.fixture('data_body'),unique()
    first = data_submit(c,body,key)
    equal(data_submit(c,body,key),first,'同键入库响应')
    equal(data_approval_ids(c,body['projectName']),[first['approvalId']],'同键入库审批数')
    equal(projects(c,body['projectName']),[],'未审批项目')


@case('TC-34-08', layer='业务', writes=True, needs='data_body data_changed_purpose')
def data_key_conflict(c):
    body,key = c.fixture('data_body'),unique()
    changed = c.fixture('data_changed_purpose')
    check(changed!=body['purpose'],'冲突夹具须改变用途')
    first = data_submit(c,body,key)
    previous = approval(c,first['approvalId'],kind='DATA_REQUEST',keyword=body['projectName'])
    c.send('POST','/data-requests',body={**body,'purpose':changed},key=key).error(409)
    equal(approval(c,first['approvalId'],kind='DATA_REQUEST',keyword=body['projectName']),previous,'原申请')
    equal(data_approval_ids(c,body['projectName']),[first['approvalId']],'冲突后的审批数')


@case('TC-34-09', layer='业务', writes=True, needs='data_upload_inputs upload_ready upload_incomplete')
def upload_request(c):
    bodies = c.many('data_upload_inputs',4)
    ids = [c.fixture('upload_ready'),c.fixture('upload_incomplete'),unique(),None]
    for i,(entry,upload_id) in enumerate(zip(bodies,ids)):
        body = {k:v for k,v in entry.items() if k not in ('sourceId','uploadId')}
        body['accessMode'] = 'FILE_UPLOAD'
        if upload_id is not None:
            body['uploadId'] = upload_id
        if i==0:
            result = data_submit(c,body)
            approval(c,result['approvalId'],kind='DATA_REQUEST',status='PENDING',keyword=body['projectName'])
            equal(projects(c,body['projectName']),[],'文件申请审批前项目')
        else:
            reject_data(c,body,'UPLOAD_NOT_READY')


def ingestion(c, target, filters):
    return row(c.all('/ingestions',query=filters),'id',target)


def dataset_query(c, env, **filters):
    return c.all('/environments/'+s(env)+'/datasets',query=filters)


def ingestion_shape(item):
    for key in ('id','sandboxId','sandboxName','environmentId','environmentType','resourceId','resourceName'):
        field(item,key,str)
    enum(item,'status',{'QUEUED','TRANSFERRING','VALIDATING','READY','FAILED','CANCELED'})
    progress = field(item,'progressPercent',(int,float))
    check(0<=progress<=100,'进度超出 0–100')
    utc(item,'createdAt')
    utc(item,'updatedAt')
    field(item,'allowedActions',list)
    if item['status']=='FAILED':
        field(item,'failureCode',str)
        field(item,'failureMessage',str)
    return item


@case('TC-35-01', needs='ingestion_filters ingestion_expected')
def ingestion_filters(c):
    filters = c.fixture('ingestion_filters')
    expected = c.fixture('ingestion_expected')
    for key in ('sandboxId','environmentId','status','keyword'):
        items = c.all('/ingestions',query={key:filters[key]})
        if key!='keyword':
            for item in items:
                subset(item,{key:filters[key]})
    c.page('/ingestions',query={**filters,'pageSize':1})
    combined = c.all('/ingestions',query=filters)
    equal(snapshot_ids(combined),snapshot_ids(expected),'入箱组合筛选')
    for fixture in expected:
        data = ingestion_shape(row(combined,'id',fixture['id']))
        subset(data,fixture,'批次预置数据')
        subset(data,{k:v for k,v in filters.items() if k!='keyword'})


def ingestion_ready(c, target, env, expected_count):
    item = c.poll(lambda:ingestion(c,target,{'environmentId':env}),lambda x:x['status']=='READY','入箱 READY')
    subset(item,{'environmentId':env,'rowCount':expected_count})
    matches = [x for x in dataset_query(c,env) if x.get('sourceIngestionId')==target]
    equal(len(matches),1,'同一批次数据集数')
    subset(matches[0],{'environmentId':env,'sourceIngestionId':target})
    return matches[0]


@case('TC-35-02', layer='业务', needs='ingestion_success_fixture',
      remainder='由联调方触发批次并准备夹具。中间态和实际数据逐行比对需借助下游证据。')
def ingestion_completed(c):
    fixture = c.fixture('ingestion_success_fixture')
    ingestion_ready(c,fixture['ingestionId'],fixture['environmentId'],3)


def retry_ingestion(c, target, client=None):
    current = client or c.client()
    return current.request('POST','/ingestions/'+s(target)+'/retry')


@case('TC-36-01', layer='业务', writes=True, needs='ingestion_retry_fixture',
      remainder='接口核对批次行数与数据集唯一性。数据集内容和重复行需通过下游数据核对。')
def retry_failed_ingestion(c):
    fixture = c.fixture('ingestion_retry_fixture')
    target,env = fixture['ingestionId'],fixture['environmentId']
    before = ingestion(c,target,{'environmentId':env})
    equal(before['status'],'FAILED','重试前批次状态')
    check('RETRY' in before['allowedActions'],'失败批次没有 RETRY')
    reply = retry_ingestion(c,target).success()
    subset(reply,{'id':target,'status':'QUEUED','progressPercent':0},'重试受理')
    ingestion_ready(c,target,env,fixture['rowCount'])


@case('TC-36-02', layer='业务', writes=True, needs='ingestion_no_retry_fixtures')
def cannot_retry_ingestion(c):
    for fixture,expected in zip(c.many('ingestion_no_retry_fixtures',3),('READY','CANCELED','FAILED')):
        target,env = fixture['ingestionId'],fixture['environmentId']
        filters = {'environmentId':env}
        original = ingestion(c,target,filters)
        equal(original['status'],expected,'批次夹具状态')
        if expected=='FAILED':
            check('RETRY' not in original['allowedActions'],'该失败夹具不得有 RETRY')
        before = snapshot_ids(dataset_query(c,env))
        retry_ingestion(c,target).error((400,403,409,422))
        equal(ingestion(c,target,filters),original,'原批次')
        equal(snapshot_ids(dataset_query(c,env)),before,'拒绝后数据集')


@case('TC-36-03', writes=True)
def missing_ingestion(c):
    retry_ingestion(c,unique()).error(404,'INGESTION_NOT_FOUND')


@case('TC-36-04', layer='业务', writes=True, needs='ingestion_retry_fixture',
      remainder='接口核对批次数与数据集唯一性，重复行和下游写入次数需单独核对。')
def concurrent_ingestion(c):
    fixture = c.fixture('ingestion_retry_fixture')
    target,env = fixture['ingestionId'],fixture['environmentId']
    original = ingestion(c,target,{'environmentId':env})
    equal(original['status'],'FAILED','并发前批次')
    check('RETRY' in original['allowedActions'],'失败批次没有 RETRY')
    clients = [c.client('A',fresh=True) for _ in range(2)]
    for client in clients:
        client.csrf()
    results = c.parallel([lambda client=client:retry_ingestion(c,target,client) for client in clients])
    check(any(r.status==200 for r in results),'两个并发请求均未受理')
    for reply in results:
        if reply.status==200:
            equal(reply.success()['id'],target,'重试返回批次')
        else:
            reply.error((400,409,422))
    ingestion_ready(c,target,env,fixture['rowCount'])


@case('TC-37-01', needs='dataset_fixtures')
def environment_datasets(c):
    for fixture in c.many('dataset_fixtures',2):
        env = fixture['environmentId']
        filters = {'keyword':fixture['keyword'],'status':'AVAILABLE'}
        path = '/environments/'+s(env)+'/datasets'
        c.page(path,query={**filters,'page':1,'pageSize':20})
        items = dataset_query(c,env,**filters)
        equal(snapshot_ids(items),snapshot_ids(fixture['items']),'环境数据集集合')
        for item in items:
            subset(item,{'environmentId':env,'status':'AVAILABLE'})
            subset(item,row(fixture['items'],'id',item['id']))
            for key in ('id','name','sandboxId','sandboxName','sourceIngestionId'):
                field(item,key,str)
            field(item,'schemaSummary',(dict,list,str))
            field(item,'size',(int,float,str))
            utc(item,'createdAt')
            field(item,'allowedActions',list)
        empty = c.page(path,query={'keyword':unique()})
        equal((empty['items'],empty['total']),([],0),'空数据集页')


def result_shape(item):
    for key in ('id','name','sandboxId','sandboxName'):
        field(item,key,str)
    field(item,'size',(int,float,str))
    utc(item,'createdAt')
    field(item,'allowedActions',list)


@case('TC-38-01', layer='业务', needs='result_visible result_other result_keyword')
def visible_results(c):
    keyword = c.fixture('result_keyword')
    query = {'keyword':keyword}
    external = c.all('/results',role='OTHER',query=query)
    row(external,'id',c.fixture('result_other'))
    own = c.all('/results',query=query)
    result_shape(row(own,'id',c.fixture('result_visible')))
    absent(own,'id',c.fixture('result_other'))


def export_create(c, payload, key=None):
    item = c.send('POST','/exports',body=payload,key=key or unique()).success()
    for name in ('exportId','approvalId'):
        field(item,name,str)
    enum(item,'status',EXPORT_STATES)
    utc(item,'updatedAt')
    return item


def exports(c, *, role='A', **filters):
    return c.all('/exports',role=role,query=filters)


def export(c, target, *, role='A', **filters):
    return row(exports(c,role=role,**filters),'id',target)


def export_ids(c, result_id, role='A'):
    return snapshot_ids([item for item in exports(c,role=role) if item.get('resultId')==result_id])


@case('TC-39-01', layer='业务', writes=True, needs='export_body')
def create_export(c):
    body = c.fixture('export_body')
    reply = export_create(c,body)
    listed = export(c,reply['exportId'])
    subset(listed,{'approvalId':reply['approvalId'],'resultId':body['resultId'],'purpose':body['purpose']})


@case('TC-39-02', layer='业务', writes=True, needs='export_body result_other')
def forbidden_export(c):
    foreign = c.fixture('result_other')
    row(c.all('/results',role='OTHER'),'id',foreign)
    before = export_ids(c,foreign,'OTHER')
    body = {**c.fixture('export_body'),'resultId':foreign}
    c.send('POST','/exports',body=body,key=unique()).error((403,404,422))
    equal(export_ids(c,foreign,'OTHER'),before,'他人结果的出箱申请')


@case('TC-39-03', writes=True, needs='export_inputs')
def export_fields(c):
    values = ('','测'*500,'测'*501,None)
    for body,purpose in zip(c.many('export_inputs',len(values)),values):
        result_id = body['resultId']
        if purpose is None:
            del body['resultId']
        else:
            body['purpose'] = purpose
        if purpose=='测'*500:
            export_create(c,body)
        else:
            before = snapshot_ids(exports(c))
            c.send('POST','/exports',body=body,key=unique()).error(400)
            equal(snapshot_ids(exports(c)),before,'无效出箱请求后的记录')


@case('TC-39-04', layer='业务', writes=True, needs='export_body')
def export_replay(c):
    body,key = c.fixture('export_body'),unique()
    before = export_ids(c,body['resultId'])
    first = export_create(c,body,key)
    equal(export_create(c,body,key),first,'同键出箱响应')
    equal(export_ids(c,body['resultId']),sorted([*before,first['exportId']]),'同键出箱新增次数')
    subset(export(c,first['exportId']),{'approvalId':first['approvalId']})


@case('TC-40-01', needs='export_state_ids export_keyword')
def export_states(c):
    states = c.fixture('export_state_ids')
    equal(set(states),set(EXPORT_STATES),'九档状态夹具')
    for stage,expected in states.items():
        filters = {'status':stage,'keyword':c.fixture('export_keyword')}
        c.page('/exports',query={**filters,'pageSize':1})
        items = exports(c,**filters)
        equal(snapshot_ids(items),sorted(expected),'出箱筛选结果')
        for item in items:
            subset(item,{'status':stage})
            for key in ('resultId','resultName','sandboxId','sandboxName','approvalId'):
                field(item,key,str)
            field(item,'allowedActions',list)
            if item.get('grantStatus') is not None:
                enum(item,'grantStatus',{'UNUSED','CONSUMED','EXPIRED'})
    empty = c.page('/exports',query={'keyword':unique()})
    equal((empty['items'],empty['total']),([],0),'空出箱页')


def delivery_retry(c, target):
    return c.send('POST','/exports/'+s(target)+'/deliveries/retry')


@case('TC-42-01', layer='业务', writes=True, needs='export_failed export_delivered',
      remainder='失败夹具的回传由联调环境控制，回传次数需查下游日志。')
def retry_delivery(c):
    failed,done = c.fixture('export_failed'),c.fixture('export_delivered')
    original = export(c,failed,status='DELIVERY_FAILED')
    delivered = export(c,done,status='DELIVERED')
    delivery_retry(c,done).error((400,403,409,422))
    equal(export(c,done,status='DELIVERED'),delivered,'已交付记录')
    reply = delivery_retry(c,failed).success()
    subset(reply,{'id':failed,'status':'DELIVERING','resultId':original['resultId']})
    result = c.poll(lambda:export(c,failed),lambda x:x['status']=='DELIVERED','出箱交付完成')
    subset(result,{'resultId':original['resultId']})


@case('TC-42-02', writes=True)
def missing_delivery(c):
    delivery_retry(c,unique()).error(404,'EXPORT_NOT_FOUND')


def export_decide(c, target, body, role):
    return c.send('POST','/exports/'+s(target)+'/decisions',role=role,body=body)


@case('TC-43-03', layer='业务', writes=True, needs='export_pending',
      remainder='前端按钮显隐和下游交付事件另核对。若已确认版本字段，在 export_decision_payload 填当前版本。')
def analyst_cannot_decide_export(c):
    target = c.fixture('export_pending')
    original = export(c,target,role='M',status='PENDING_APPROVAL')
    payload = {**c.values.get('export_decision_payload',{}),'decision':'APPROVE'}
    export_decide(c,target,payload,'A').error(403)
    equal(export(c,target,role='M',status='PENDING_APPROVAL'),original,'越权后的出箱记录')


@case('TC-43-05', writes=True)
def missing_export_decision(c):
    body = {**c.values.get('export_decision_payload',{}),'decision':'APPROVE'}
    export_decide(c,unique(),body,'M').error(404,'EXPORT_NOT_FOUND')
