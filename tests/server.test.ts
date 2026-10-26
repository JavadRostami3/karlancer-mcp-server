import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {DomainService} from '../src/domain.js';
import {registerMcpTools} from '../src/server.js';
import {Store} from '../src/store.js';

test('prepare_proposal returns both textual JSON and nonempty structured MCP content', async () => {
  const directory=mkdtempSync(join(tmpdir(),'karlancer-mcp-output-'));
  const store=new Store(join(directory,'state.sqlite'),Buffer.alloc(32,11));
  const tenant='tenant';
  const input={
    project_ref:336158,
    description:'برنامهٔ اجرا و تحویل دو مرحله‌ای را با گزارش روشن و قابل بررسی ارائه می‌کنم.',
    milestones:[
      {description:'مرحلهٔ اول پیاده‌سازی',duration:1,budget:3500000},
      {description:'مرحلهٔ دوم تست و تحویل',duration:1,budget:4000000},
    ],
  };
  let server:McpServer|undefined;
  let client:Client|undefined;
  try {
    store.seal(tenant,'karlancer',{accountId:713391,token:'fixture-token'});
    store.put('policy',tenant,{version:1,proposalsEnabled:true,repliesEnabled:false,minNetIncome:0,maxDurationDays:30,dailyMaxProposals:5,dailyMaxTokens:20,dailyMaxStatistics:0,cashPremiumLimit:0,allowIncludedPromotions:false,aiFields:[]});
    const domain=new DomainService({store,logger:()=>{},clientFor:()=>({
      getProfile:async()=>({user:{id:713391}}),
      getProject:async()=>({id:336158,status:'pending',min_budget:4500000,max_budget:9000000,bid_token_cost:4,employer_id:99,skills:[{id:7}]}),
      getPlans:async()=>({commission_percent:10,available_tokens:8}),
    }) as any});
    server=new McpServer({name:'fixture',version:'1'});
    registerMcpTools(server,domain,tenant,['profile:read','proposals:write']);
    const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client=new Client({name:'fixture-client',version:'1'});
    await client.connect(clientTransport);

    const result=await client.callTool({name:'prepare_proposal',arguments:input});
    const structured=result.structuredContent as Record<string,unknown>;
    const text=result.content.find((item):item is {type:'text';text:string}=>item.type==='text')?.text;
    assert.notEqual(result.isError,true);
    assert.equal(typeof structured.draft_id,'string');
    assert.equal(structured.status,'PREPARED');
    assert.equal(JSON.parse(text??'null').draft_id,structured.draft_id);
    assert.equal(JSON.parse(text??'null').status,'PREPARED');

    const rejected=await client.callTool({name:'prepare_proposal',arguments:{...input,milestones:[
      {description:'مرحلهٔ اول پیاده‌سازی',duration:1,budget:4500000},
      {description:'مرحلهٔ دوم تست و تحویل',duration:1,budget:5000000},
    ]}});
    const errorText=rejected.content.find((item):item is {type:'text';text:string}=>item.type==='text')?.text;
    const error=JSON.parse(errorText??'null');
    assert.equal(rejected.isError,true);
    assert.equal(error.error,'BUDGET_CAP_EXCEEDED');
    assert.equal(typeof error.request_id,'string');
    assert.notEqual(errorText,'{}');
  } finally {
    await client?.close();
    await server?.close();
    store.close();
    rmSync(directory,{recursive:true,force:true});
  }
});
