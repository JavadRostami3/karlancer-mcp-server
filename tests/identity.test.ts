import assert from 'node:assert/strict';
import {createServer, type Server} from 'node:http';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import test from 'node:test';
import express from 'express';
import helmet from 'helmet';
import {DatabaseSync} from 'node:sqlite';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {DomainService} from '../src/domain.js';
import {installIdentity,identityErrorDiagnostic} from '../src/identity.js';
import {createApp,registerMcpTools} from '../src/server.js';
import {KarlancerClient} from '../src/karlancer.js';
import {Store} from '../src/store.js';
import {oauthHttpTrace,sanitizeOAuthCspReport,mcpProtocolTrace} from '../src/oauth-trace.js';

const googleRedirects=[
  'https://oauth-redirect.googleusercontent.com/r/gemini-one',
  'https://oauth-redirect.googleusercontent.com/r/gemini-two',
  'https://oauth-redirect-sandbox.googleusercontent.com/r/gemini-one',
  'https://oauth-redirect-sandbox.googleusercontent.com/r/gemini-two',
  'https://oauth-redirect-test.googleusercontent.com/r/gemini-one',
  'https://oauth-redirect-test.googleusercontent.com/r/gemini-two',
];
const owner='713391';
const resourceFor=(baseUrl:string)=>`${baseUrl}/mcp`;
const geminiScopes='mcp profile:read profile:write projects:read proposals:read proposals:write conversations:read conversations:write';
type Harness=Awaited<ReturnType<typeof harness>>;
const handoffTarget=(html:string)=>html.match(/id="oauth-callback" href="([^"]+)"/)?.[1]?.replace(/&(?:amp|lt|gt|quot|#39);/g,value=>({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&#39;':"'"})[value]!);

test('interaction diagnostics reveal allowlisted causes without request or error credentials',()=>{
  const secret='fixture-sensitive-value';
  const req={route:{path:'/interaction/:uid'},method:'POST',originalUrl:`/interaction/${secret}?code=${secret}`,headers:{cookie:secret,authorization:secret},body:{csrf:secret}} as any;
  assert.deepEqual(identityErrorDiagnostic(req,{name:'SessionNotFound',status:400,message:'invalid_request',error_description:'interaction session id cookie not found'}),{route:'/interaction/:uid',method:'POST',error:{name:'SessionNotFound',status:400,message:'interaction session id cookie not found'}});
  const diagnostic=identityErrorDiagnostic(req,{name:secret,status:400,message:secret,error_description:secret});
  assert.equal(JSON.stringify(diagnostic).includes(secret),false);
  assert.deepEqual(Object.keys(diagnostic!),['route','method','error']);
});

class CookieJar {
  private readonly values=new Map<string,{name:string;value:string;domain:string;hostOnly:boolean;path:string;secure:boolean;expires:number;created:number}>();
  private sequence=0;
  absorb(response:Response,url:URL) {
    for(const line of response.headers.getSetCookie()) {
      const [pair,...attributes]=line.split(';').map(value=>value.trim());
      const split=pair.indexOf('=');
      if(split<1)continue;
      const name=pair.slice(0,split),value=pair.slice(split+1);
      const attrs=new Map(attributes.map(attribute=>{const index=attribute.indexOf('=');return index<0?[attribute.toLowerCase(),'']:[attribute.slice(0,index).toLowerCase(),attribute.slice(index+1)];}));
      const domain=(attrs.get('domain')??url.hostname).replace(/^\./,'').toLowerCase();
      if(url.hostname!==domain&&!url.hostname.endsWith(`.${domain}`))continue;
      const defaultPath=url.pathname.slice(0,url.pathname.lastIndexOf('/'))||'/';
      const path=attrs.get('path')?.startsWith('/')?attrs.get('path')!:defaultPath;
      const key=JSON.stringify([name,domain,path]);
      const expires=attrs.has('max-age')?Date.now()+Number(attrs.get('max-age'))*1000:attrs.has('expires')?Date.parse(attrs.get('expires')!):Infinity;
      if(expires<=Date.now())this.values.delete(key);
      else this.values.set(key,{name,value,domain,hostOnly:!attrs.has('domain'),path,secure:attrs.has('secure'),expires,created:this.values.get(key)?.created??this.sequence++});
    }
  }
  header(url:URL) {
    return [...this.values.values()].filter(cookie=>cookie.expires>Date.now()&&
      (cookie.hostOnly?url.hostname===cookie.domain:url.hostname===cookie.domain||url.hostname.endsWith(`.${cookie.domain}`))&&
      (!cookie.secure||url.protocol==='https:')&&
      (url.pathname===cookie.path||url.pathname.startsWith(cookie.path.endsWith('/')?cookie.path:`${cookie.path}/`)))
      .sort((a,b)=>b.path.length-a.path.length||a.created-b.created)
      .map(({name,value})=>`${name}=${value}`).join('; ');
  }
}

test('browser cookies preserve equal names by path and send longer paths before older root cookies',()=>{
  const jar=new CookieJar();
  const url=new URL('https://mcp.fixture.example/interaction/current');
  jar.absorb(new Response(null,{headers:[['set-cookie','interaction=old-root; Path=/; Secure'],['set-cookie','interaction=current; Path=/interaction/current; Secure'],['set-cookie','signature=older; Path=/interaction/current; Secure']]}),url);
  assert.equal(jar.header(url),'interaction=current; signature=older; interaction=old-root');
  assert.equal(jar.header(new URL('https://mcp.fixture.example/interaction/current-suffix')),'interaction=old-root');
  assert.equal(jar.header(new URL('https://mcp.fixture.example/oidc/token')),'interaction=old-root');
  assert.equal(jar.header(new URL('http://mcp.fixture.example/interaction/current')),'');
  jar.absorb(new Response(null,{headers:{'set-cookie':'interaction=; Path=/interaction/current; Max-Age=0'}}),url);
  assert.equal(jar.header(url),'signature=older; interaction=old-root');
});

test('portal browser login rejects missing interaction cookies and reaches confidential code, token and refresh',async(t)=>{
  const directory=mkdtempSync(join(tmpdir(),'karlancer-browser-'));
  const store=new Store(join(directory,'state.sqlite'),Buffer.alloc(32,12));
  const baseUrl='https://mcp.fixture.example';
  const phone='09120000000',normalized=phone.slice(1);
  const phoneHash=createHash('sha256').update(normalized).digest('hex');
  store.put('users',owner,{id:owner,name:'Test Owner',phoneHash,accountId:Number(owner),admin:true});
  t.mock.method(KarlancerClient.prototype,'requestOtp',async()=>({success:true}));
  t.mock.method(KarlancerClient.prototype,'verifyOtp',async()=>({user:{id:Number(owner),role:'freelancer',phone},access_token:'fixture-upstream-token',token_type:'Bearer'}));
  const {app,provider}=await createApp({store,baseUrl,ownerPhoneHash:phoneHash});
  const diagnosticDeadline=process.env.OAUTH_DIAGNOSTICS_UNTIL;
  process.env.OAUTH_DIAGNOSTICS_UNTIL=String(Date.now()+60_000);
  const diagnostics:unknown[]=[];
  t.mock.method(console,'warn',(message:unknown)=>diagnostics.push(JSON.parse(String(message))));
  const server=createServer(app);
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=server.address();assert(address&&typeof address!=='string');
  const jar=new CookieJar();
  jar.absorb(new Response(null,{headers:[['set-cookie','_interaction=stale-root; Path=/; Secure'],['set-cookie','_interaction.sig=stale-root-signature; Path=/; Secure']]}),new URL(baseUrl));
  const request=async(path:string,init:RequestInit={})=>{
    const url=new URL(path,baseUrl),headers=new Headers(init.headers);
    headers.set('x-forwarded-proto','https');headers.set('x-forwarded-host',url.host);headers.set('host',url.host);
    const cookie=jar.header(url);if(cookie&&!headers.has('cookie'))headers.set('cookie',cookie);
    const response=await fetch(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`,{...init,headers,redirect:'manual'});
    jar.absorb(response,url);return response;
  };
  const postForm=(path:string,fields:Record<string,string>)=>request(path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:baseUrl},body:new URLSearchParams(fields)});
  const csrfFrom=async(response:Response)=>{assert.equal(response.status,200);const csrf=(await response.text()).match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];assert(csrf);return csrf;};
  try {
    const registration=await request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'Google',token_endpoint_auth_method:'client_secret_post',grant_types:['authorization_code','refresh_token'],response_types:['code'],redirect_uris:googleRedirects})});
    assert.equal(registration.status,201);
    const registered=await registration.json() as Record<string,string>;
    let expectedFormOrigin='https://oauth-redirect.googleusercontent.com';
    let loggedIn=false;
    let cookieRejectionChecked=false;
    const browserRequest=async(path:string,init:RequestInit={})=>{
      const response=await request(path,init);
      if(new URL(path,baseUrl).pathname==='/oidc/auth') {
        assert.equal(response.status,303,'The initial OIDC authorization request must redirect to its interaction');
        const isGoogleCallback=googleRedirects.some(redirect=>new URL(redirect).origin===expectedFormOrigin);
        const expectedOpener=isGoogleCallback?'unsafe-none':'same-origin';
        assert.equal(response.headers.get('cross-origin-opener-policy'),expectedOpener,'Only validated Google OAuth redirects may preserve the Gemini popup callback channel');
      }
      if(new URL(path,baseUrl).pathname.startsWith('/interaction/')&&(!init.method||init.method==='GET')&&response.status===200) {
        const csp=response.headers.get('content-security-policy')!;
        const formAction=csp.split(';').map(value=>value.trim()).find(value=>value.startsWith('form-action '));
        assert.equal(formAction,"form-action 'self' "+expectedFormOrigin,'The rendered consent policy must permit only its validated callback origin');
        assert.equal(response.headers.get('cross-origin-opener-policy'),googleRedirects.some(redirect=>new URL(redirect).origin===expectedFormOrigin)?'unsafe-none':'same-origin','Only registered Google callbacks may preserve the Gemini popup channel');
        assert(csp.split(';').includes("script-src 'self'"));
        assert(csp.split(';').includes("frame-ancestors 'none'"));
        assert(!csp.includes('https:;'));
      }
      if(new URL(path,baseUrl).pathname.startsWith('/interaction/')&&init.method==='POST'&&response.status===303) {
        const csp=response.headers.get('content-security-policy')!;
        const formAction=csp.split(';').map(value=>value.trim()).find(value=>value.startsWith('form-action '));
        assert.equal(formAction,"form-action 'self' "+expectedFormOrigin,'The consent POST redirect must permit only its validated callback origin');
        assert.equal(response.headers.get('cross-origin-opener-policy'),googleRedirects.some(redirect=>new URL(redirect).origin===expectedFormOrigin)?'unsafe-none':'same-origin','Only registered Google callbacks may preserve the Gemini popup channel');
        assert(csp.split(';').includes("script-src 'self'"));
        assert(csp.split(';').includes("frame-ancestors 'none'"));
        assert(!csp.includes('https:;'));
      }
      if(new URL(path,baseUrl).pathname.startsWith('/oidc/auth/')&&response.status===303) {
        const csp=response.headers.get('content-security-policy')!;
        const formAction=csp.split(';').map(value=>value.trim()).find(value=>value.startsWith('form-action '));
        assert.equal(formAction,"form-action 'self' "+expectedFormOrigin,'The final authorization redirect must permit only its validated callback origin');
        assert.equal(response.headers.get('cross-origin-opener-policy'),googleRedirects.some(redirect=>new URL(redirect).origin===expectedFormOrigin)?'unsafe-none':'same-origin','Only registered Google callbacks may preserve the Gemini popup channel');
        assert(csp.split(';').includes("script-src 'self'"));
        assert(csp.split(';').includes("frame-ancestors 'none'"));
        assert(!csp.includes('https:;'));
      }
      if(!cookieRejectionChecked&&new URL(path,baseUrl).pathname.startsWith('/interaction/')&&(!init.method||init.method==='GET')&&response.status===200) {
        const csrf=await csrfFrom(response.clone());
        const rejected=await request(path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:baseUrl,cookie:''},body:new URLSearchParams({csrf,decision:'approve'})});
        assert.equal(rejected.status,400);
        assert.deepEqual(await rejected.json(),{error:'invalid_request'});
        assert.deepEqual(diagnostics,[{route:'/interaction/:uid',method:'POST',error:{name:'SessionNotFound',status:400,message:'interactionDetails: interaction session id cookie not found'}}]);
        cookieRejectionChecked=true;
      }
      return response;
    };
    const code=await authorizationCode({baseUrl,request:browserRequest},registered.client_id,googleRedirects[0],{state:'portal-browser-fixture',scope:geminiScopes,login:async(url,response)=>{
      const csrf=await csrfFrom(response);
      const requested=await postForm('/login/request',{csrf,phone});assert.equal(requested.status,303);
      const verifyCsrf=await csrfFrom(await request(requested.headers.get('location')!));
      const verified=await postForm('/login/verify',{csrf:verifyCsrf,code:'123456'});assert.equal(verified.status,303);
      loggedIn=true;
      return new URL(verified.headers.get('location')!,url);
    }});
    assert.equal(loggedIn,true);
    assert.equal(cookieRejectionChecked,true);
    const exchanged=await tokenRequest({request},{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0]});
    assert.equal(exchanged.response.status,200);
    const access=await provider.AccessToken.find(exchanged.body.access_token);
    assert.equal(access.accountId,owner);assert.equal(access.aud,resourceFor(baseUrl));
    assert.deepEqual([...access.scopes].sort(),geminiScopes.split(' ').sort());
    const refreshed=await tokenRequest({request},{grant_type:'refresh_token',client_id:registered.client_id,client_secret:registered.client_secret,refresh_token:exchanged.body.refresh_token});
    assert.equal(refreshed.response.status,200);
    expectedFormOrigin='https://chatgpt.com';
    const publicRedirect='https://chatgpt.com/connector/oauth/callback';
    const publicRegistration=await request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'ChatGPT',token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],redirect_uris:[publicRedirect]})});
    assert.equal(publicRegistration.status,201);
    const publicClient=await publicRegistration.json() as Record<string,string>;
    const verifier='chatgpt-csp-regression-verifier-01234567890';
    const challenge=createHash('sha256').update(verifier).digest('base64url');
    const publicCode=await authorizationCode({baseUrl,request:browserRequest},publicClient.client_id,publicRedirect,{state:'chatgpt-csp-regression',challenge});
    const publicTokens=await tokenRequest({request},{grant_type:'authorization_code',client_id:publicClient.client_id,code:publicCode,redirect_uri:publicRedirect,code_verifier:verifier});
    assert.equal(publicTokens.response.status,200);
    assert(Boolean(await provider.AccessToken.find(exchanged.body.access_token)),'Existing Gemini token must remain valid after a public PKCE connection');
    const portal=await request('/login');
    assert.equal(portal.headers.get('content-security-policy')!.split(';').find(value=>value.trim().startsWith('form-action '))!.trim(),"form-action 'self'",'Other portal forms keep same-origin policy');
  } finally {
    if(diagnosticDeadline===undefined)delete process.env.OAUTH_DIAGNOSTICS_UNTIL;else process.env.OAUTH_DIAGNOSTICS_UNTIL=diagnosticDeadline;
    await new Promise<void>(resolve=>server.close(()=>resolve()));store.close();rmSync(directory,{recursive:true,force:true});
  }
});

async function harness(options:{https?:boolean;trace?:boolean;headers?:boolean}={}) {
  const directory=mkdtempSync(join(tmpdir(),'karlancer-oidc-'));
  const dbPath=join(directory,'state.sqlite');
  const store=new Store(dbPath,Buffer.alloc(32,31));
  store.put('users',owner,{id:owner,name:'Test Owner'});
  store.put('users','other-account',{id:'other-account',name:'Other Owner'});
  store.seal(owner,'karlancer',{accountId:Number(owner),token:'fixture-karlancer-token'});
  const app=express();
  app.set('trust proxy',1);
  if(options.headers)app.use(helmet({referrerPolicy:{policy:'same-origin'}}));
  const server:Server=createServer(app);
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const address=server.address();
  assert(address&&typeof address!=='string');
  const transportOrigin=`http://127.0.0.1:${address.port}`;
  const baseUrl=options.https?'https://mcp.fixture.example':transportOrigin;
  if(options.trace)app.use(oauthHttpTrace(baseUrl));
  let account:string|undefined=owner;
  const identity=await installIdentity(app,{store,baseUrl,getPortalAccount:()=>account});
  const domain=new DomainService({store,logger:()=>{},clientFor:()=>({getProfile:async()=>({user:{id:Number(owner),role:'freelancer'}})}) as any});
  app.post('/mcp',express.json(),mcpProtocolTrace(['get_connection_status','get_profile']),identity.requireMcp,async(req,res)=>{
    const auth=(req as any).auth;
    const mcp=new McpServer({name:'karlancer-mcp-fixture',version:'1'});
    registerMcpTools(mcp,domain,auth.extra.tenantId,auth.scopes);
    const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true});
    res.on('close',()=>{void transport.close();void mcp.close();});
    try {await mcp.connect(transport);await transport.handleRequest(req,res,(req as any).body);}
    catch {if(!res.headersSent)res.status(500).json({error:'internal_error'});}
  });
  const diagnostics:unknown[]=[];
  app.use((error:any,req:express.Request,res:express.Response,_next:express.NextFunction)=>{
    diagnostics.push(identityErrorDiagnostic(req,error));
    res.status(error?.status===400?400:500).json({error:error?.status===400?'invalid_request':'internal_error'});
  });
  const jar=new CookieJar();
  const request=async(path:string,init:RequestInit={})=>{
    const url=new URL(path,baseUrl);
    const headers=new Headers(init.headers);
    if(jar.header(url)&&!headers.has('cookie'))headers.set('cookie',jar.header(url));
    if(options.https) {headers.set('x-forwarded-proto','https');headers.set('x-forwarded-host',url.host);headers.set('host',url.host);}
    const response=await fetch(new URL(url.pathname+url.search,transportOrigin),{...init,headers,redirect:'manual'});
    jar.absorb(response,url);
    return response;
  };
  const close=async()=>{
    await new Promise<void>(resolve=>server.close(()=>resolve()));
    store.close();
    rmSync(directory,{recursive:true,force:true});
  };
  return {baseUrl,dbPath,identity,request,close,diagnostics,cookies:jar,setAccount:(value:string)=>{account=value;},replaceApp:(replacement:express.Express)=>{server.removeAllListeners('request');server.on('request',replacement);}};
}

test('Google code callbacks commit a restricted handoff document while ChatGPT public callbacks retain redirects',async()=>{
  const client=await harness({https:true,headers:true});
  try {
    const {response,body:google}=await register(client,'client_secret_post');assert.equal(response.status,201);
    let handoff=false;
    const request=async(path:string,init:RequestInit={})=>{
      const result=await client.request(path,init);
      if(new URL(path,client.baseUrl).pathname.startsWith('/oidc/auth/')&&result.status===200) {
        const html=await result.clone().text();
        if(html.includes('id="oauth-callback"')) {
          handoff=true;
          assert.match(result.headers.get('content-type')??'',/text\/html/);
          assert.match(result.headers.get('cache-control')??'',/no-store/);
          assert.equal(result.headers.get('location'),null);
          const formAction=(result.headers.get('content-security-policy')??'').split(';').map(x=>x.trim()).find(x=>x.startsWith('form-action '));
          assert.equal(formAction,"form-action 'self'");
          assert.match(html,/http-equiv="refresh"/);
        }
      }
      return result;
    };
    const state='fixture-state-with-"-and-&-characters';
    const googleCode=await authorizationCode({...client,request},google.client_id,googleRedirects[0],{state});
    assert.equal(handoff,true,'A Google callback after consent must leave the form-navigation redirect chain');
    const tokens=await tokenRequest(client,{grant_type:'authorization_code',client_id:google.client_id,client_secret:google.client_secret,code:googleCode,redirect_uri:googleRedirects[0]});assert.equal(tokens.response.status,200);
    const callback='https://chatgpt.com/connector/oauth/callback';
    const registered=await client.request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'ChatGPT',token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],redirect_uris:[callback]})});assert.equal(registered.status,201);
    const publicClient=await registered.json() as Record<string,string>;
    const verifier='chatgpt-preserved-pkce-verifier-0123456789abcd',challenge=createHash('sha256').update(verifier).digest('base64url');
    handoff=false;
    const publicCode=await authorizationCode({...client,request},publicClient.client_id,callback,{state:'public-callback-state',challenge});
    assert.equal(handoff,false,'Non-Google callbacks must retain the provider redirect behavior');
    const publicTokens=await tokenRequest(client,{grant_type:'authorization_code',client_id:publicClient.client_id,code:publicCode,redirect_uri:callback,code_verifier:verifier});assert.equal(publicTokens.response.status,200);
    assert.equal((await tokenRequest(client,{grant_type:'refresh_token',client_id:publicClient.client_id,refresh_token:publicTokens.body.refresh_token})).response.status,200);
  } finally {await client.close();}
});

test('OAuth callback tracing correlates code and token outcomes without recording credentials',async(t)=>{
  const previous=process.env.OAUTH_TRACE_UNTIL;process.env.OAUTH_TRACE_UNTIL=String(Date.now()+60_000);
  const traces:any[]=[];t.mock.method(console,'info',(message:unknown)=>{traces.push(JSON.parse(String(message)));});
  const client=await harness({https:true,trace:true});
  try {
    const {response,body:registered}=await register(client,'client_secret_post');assert.equal(response.status,201);
    const verifier='callback-trace-pkce-verifier-0123456789-abcdefgh';
    const challenge=createHash('sha256').update(verifier).digest('base64url');
    const state='fixture-private-oauth-state';
    const code=await authorizationCode(client,registered.client_id,googleRedirects[0],{state,challenge});
    const fields={grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0],code_verifier:verifier};
    assert.equal((await tokenRequest(client,{...fields,client_secret:'fixture-private-wrong-secret'})).response.status,401);
    const exchanged=await tokenRequest(client,fields);assert.equal(exchanged.response.status,200);
    const refreshed=await tokenRequest(client,{grant_type:'refresh_token',client_id:registered.client_id,client_secret:registered.client_secret,refresh_token:exchanged.body.refresh_token});assert.equal(refreshed.response.status,200);
    const mcp=new Client({name:'trace-fixture',version:'1'});
    try {
      await mcp.connect(new StreamableHTTPClientTransport(new URL(`${client.transportOrigin}/mcp`),{requestInit:{headers:{authorization:`Bearer ${refreshed.body.access_token}`}}}));
      const result=await mcp.callTool({name:'get_connection_status',arguments:{}});assert.equal(result.structuredContent?.status,'CONNECTED');
      const call=traces.find(x=>x.event==='mcp_rpc'&&x.rpc_method==='tools/call');
      assert(call);assert.equal(call.client_class,'google');assert.equal(call.tool,'get_connection_status');assert.equal(call.outcome,'success');assert.equal(call.connection_status,'CONNECTED');
    } finally {await mcp.close();}
    assert.equal((await tokenRequest(client,fields)).response.status,400);
    const authorization=traces.find(x=>x.event==='oauth_authorization_result');
    assert(authorization,'The real provider authorization event must be traced');
    assert.equal(authorization.client_class,'google');assert.equal(authorization.state_preserved,true);assert.equal(authorization.issuer_matches,true);
    assert.equal(authorization.callback_registered,true);assert.equal(authorization.callback_origin,'google_callback');assert.equal(authorization.response_mode,'query');
    const http=traces.filter(x=>x.event==='oauth_http'&&x.route==='/oidc/token');
    assert.deepEqual(http.map(x=>x.status),[401,200,200,400]);
    assert(http.some(x=>x.request_id===exchanged.response.headers.get('x-oauth-diagnostic-id')),'The HTTP response must expose the generated diagnostic ID used by the edge trace');
    for(const result of traces.filter(x=>x.event==='oauth_token_result'))assert(http.some(x=>x.request_id===result.request_id),'Provider events must share the HTTP request correlation ID');
    assert.equal(traces.filter(x=>x.event==='oauth_token_result').length,4);
    const report=await client.request('/oidc/diagnostics/csp',{method:'POST',headers:{'content-type':'application/csp-report'},body:JSON.stringify({'csp-report':{'document-uri':`${client.baseUrl}/interaction/fixture-private-uid?state=${state}`,'blocked-uri':`https://gemini.google.com/fixture?code=${code}`,'effective-directive':'form-action','original-policy':registered.client_secret,'script-sample':verifier,disposition:'enforce'}})});
    assert.equal(report.status,204);
    const violation=traces.find(x=>x.event==='oauth_csp_violation');assert(violation);assert.equal(violation.blocked_origin,'gemini');assert.equal(violation.directive,'form-action');
    const serialized=JSON.stringify(traces);
    for(const sensitive of [state,code,registered.client_secret,exchanged.body.access_token,exchanged.body.refresh_token,verifier,'fixture-private-wrong-secret','fixture-private-uid'])assert.equal(serialized.includes(sensitive),false,'Trace output must omit credential values');
  } finally {if(previous===undefined)delete process.env.OAUTH_TRACE_UNTIL;else process.env.OAUTH_TRACE_UNTIL=previous;await client.close();}
});

test('CSP report diagnostics discard URLs, account-like paths, samples and untrusted origin names',()=>{
  const report=sanitizeOAuthCspReport({'csp-report':{'document-uri':'https://mcp.fixture.example/interaction/private-value?csrf=private-value','blocked-uri':'https://private-value.example/secret?token=private-value','effective-directive':'form-action','script-sample':'private-value',disposition:'enforce'}},'https://mcp.fixture.example');
  assert.deepEqual(report,{event:'oauth_csp_violation',route:'/interaction/:uid',directive:'form-action',blocked_origin:'other',disposition:'enforce'});
  assert.equal(sanitizeOAuthCspReport({'csp-report':{'document-uri':'https://untrusted.example/interaction/value'}},'https://mcp.fixture.example'),undefined);
});

test('MCP diagnostics distinguish discovery, calls and protocol errors without logging payloads',async(t)=>{
  const previous=process.env.OAUTH_TRACE_UNTIL;process.env.OAUTH_TRACE_UNTIL=String(Date.now()+60_000);
  const traces:any[]=[];t.mock.method(console,'info',(message:unknown)=>traces.push(JSON.parse(String(message))));
  const app=express();app.use(oauthHttpTrace('https://fixture.example'),express.json(),mcpProtocolTrace(['get_connection_status']));
  app.post('/mcp',(req,res)=>{
    (req as any).auth={extra:{clientClass:'google'}};
    const payload=req.body.params?.arguments;
    if(req.body.method==='tools/list')res.json({jsonrpc:'2.0',id:req.body.id,result:{tools:[{private:'fixture-private-value'}]}});
    else if(req.body.params?.name==='get_connection_status') {
      const response={jsonrpc:'2.0',id:req.body.id,result:payload?.fail?{isError:true,content:[{type:'text',text:JSON.stringify({error:'REAUTH_REQUIRED',message:'fixture-private-value'})}]}:{structuredContent:{status:'CONNECTED',account_id:999},content:[{type:'text',text:'fixture-private-value'}]}};
      const encoded=JSON.stringify(response);res.type('json');res.write(encoded.slice(0,40));res.end(encoded.slice(40));
    } else res.json({jsonrpc:'2.0',id:req.body.id,error:{code:-32602,message:'fixture-private-value',data:'fixture-private-value'}});
  });
  const server=createServer(app);await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=server.address();assert(address&&typeof address!=='string');
  try {
    for(const body of [
      {method:'tools/list'},
      {method:'tools/call',params:{name:'get_connection_status',arguments:{private:'fixture-private-value'}}},
      {method:'tools/call',params:{name:'get_connection_status',arguments:{fail:true}}},
      {method:'tools/call',params:{name:'fixture-private-value'}},
    ]) {
      const response=await fetch(`http://127.0.0.1:${address.port}/mcp`,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer fixture-private-value',cookie:'private=fixture-private-value'},body:JSON.stringify({jsonrpc:'2.0',id:'fixture-private-value',...body})});
      assert.equal(response.status,200);await response.text();
    }
    const rpc=traces.filter(x=>x.event==='mcp_rpc');assert.equal(rpc.length,4);
    assert.deepEqual(rpc.map(x=>x.rpc_method),['tools/list','tools/call','tools/call','tools/call']);
    assert.deepEqual(rpc.map(x=>x.outcome),['success','success','tool_error','protocol_error']);
    assert.equal(rpc[1].tool,'get_connection_status');assert.equal(rpc[1].connection_status,'CONNECTED');
    assert.equal(rpc[2].error_code,'REAUTH_REQUIRED');assert.equal(rpc[3].rpc_error_code,-32602);assert.equal(rpc[3].tool,'other');
    assert(rpc.every(x=>x.client_class==='google'&&x.http_status===200));
    assert(rpc.every(x=>traces.some(y=>y.event==='oauth_http'&&y.request_id===x.request_id)));
    assert.equal(JSON.stringify(traces).includes('fixture-private-value'),false);
    process.env.OAUTH_TRACE_UNTIL='0';
    const response=await fetch(`http://127.0.0.1:${address.port}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({method:'tools/list'})});await response.text();
    assert.equal(traces.filter(x=>x.event==='mcp_rpc').length,4);
  } finally {
    if(previous===undefined)delete process.env.OAUTH_TRACE_UNTIL;else process.env.OAUTH_TRACE_UNTIL=previous;
    await new Promise<void>(resolve=>server.close(()=>resolve()));
  }
});

test('retired signed root cookies cannot shadow the path-scoped interaction for Gemini or public PKCE clients',async(t)=>{
  for(const method of ['client_secret_post','none'] as const)for(const order of ['path-first','root-first','signature-first'])await t.test(`${method}, ${order}`,async()=>{
    const client=await harness({https:true});
    try {
      const {response,body:registered}=await register(client,'none');assert.equal(response.status,201);
      const verifier='browser-cookie-order-pkce-verifier-0123456789';
      const publicChallenge=createHash('sha256').update(verifier).digest('base64url');
      const challenge=method==='none'?publicChallenge:undefined;
      let retiredCookies:string[]=[];
      const firstRequest=async(path:string,init:RequestInit={})=>{
        const result=await client.request(path,init);
        const url=new URL(path,client.baseUrl);
        if(url.pathname.startsWith('/interaction/')&&(!init.method||init.method==='GET')&&result.status===200)retiredCookies=client.cookies.header(url).split('; ').filter(pair=>/^_interaction(?:\.sig)?=/.test(pair));
        return result;
      };
      const publicCode=await authorizationCode({...client,request:firstRequest},registered.client_id,googleRedirects[0],{state:'retired-flow',challenge:publicChallenge});
      const publicTokens=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,code:publicCode,redirect_uri:googleRedirects[0],code_verifier:verifier});
      assert.equal(publicTokens.response.status,200);
      assert.equal(retiredCookies.length,2);
      client.cookies.absorb(new Response(null,{headers:retiredCookies.map(pair=>['set-cookie',`${pair}; Path=/; Secure; HttpOnly; SameSite=Lax`])}),new URL(client.baseUrl));
      const {response:freshRegistration,body:freshClient}=await register(client,method);assert.equal(freshRegistration.status,201);
      let interactionRequests=0;
      const request=async(path:string,init:RequestInit={})=>{
        const url=new URL(path,client.baseUrl);
        if(url.pathname.startsWith('/interaction/')) {
          interactionRequests++;
          const parts=client.cookies.header(url).split('; ');
          assert.equal(parts.filter(pair=>pair.startsWith('_interaction=')).length,2);
          const headers=new Headers(init.headers);
          if(init.method==='POST') {
            assert(Boolean(await client.identity.provider.Interaction.find(url.pathname.split('/').at(-1))),'Fresh interaction must still be stored before consent');
            if(order==='root-first')headers.set('cookie',[...retiredCookies,...parts.filter(pair=>!retiredCookies.includes(pair))].join('; '));
            if(order==='signature-first')headers.set('cookie',[...parts.filter(pair=>!pair.startsWith('_interaction.sig=')),...retiredCookies.filter(pair=>pair.startsWith('_interaction.sig=')),...parts.filter(pair=>pair.startsWith('_interaction.sig=')&&!retiredCookies.includes(pair))].join('; '));
            if(order==='root-first') {
              const forged=new Headers(headers);
              forged.set('cookie',[...parts.filter(pair=>!pair.startsWith('_interaction.sig=')),...retiredCookies.filter(pair=>pair.startsWith('_interaction.sig=')),'_interaction.sig=forged-signature'].join('; '));
              const denied=await client.request(path,{...init,headers:forged});assert.equal(denied.status,400);
              const wrongCsrf=new URLSearchParams(String(init.body));wrongCsrf.set('csrf','forged-csrf');
              assert.equal((await client.request(path,{...init,headers,body:wrongCsrf})).status,403);
              const foreignOrigin=new Headers(headers);foreignOrigin.set('origin','https://untrusted.fixture.example');
              assert.equal((await client.request(path,{...init,headers:foreignOrigin})).status,403);
            }
          }
          init={...init,headers};
        }
        return client.request(path,init);
      };
      let code:string;
      try {code=await authorizationCode({...client,request},freshClient.client_id,googleRedirects[0],{state:'fresh-flow',challenge});}
      catch {assert.fail(`Fresh interaction rejected: ${JSON.stringify(client.diagnostics)}`);}
      assert(interactionRequests>=2,'Fresh client must render and submit consent');
      const exchanged=await tokenRequest(client,{grant_type:'authorization_code',client_id:freshClient.client_id,...(method==='client_secret_post'?{client_secret:freshClient.client_secret}:{code_verifier:verifier}),code,redirect_uri:googleRedirects[0]});
      assert.equal(exchanged.response.status,200);
      assert(Boolean(await client.identity.provider.AccessToken.find(publicTokens.body.access_token)),'Existing public-client token must remain valid');
      const refreshed=await tokenRequest(client,{grant_type:'refresh_token',client_id:registered.client_id,refresh_token:publicTokens.body.refresh_token});
      assert.equal(refreshed.response.status,200,'Existing public client must still refresh after a new connection');
    } finally {await client.close();}
  });
});

test('PersistentAdapter updates atomically, survives reopen, expires at TTL and destroys only the requested interaction',async(t)=>{
  const client=await harness();
  let reopened:Store|undefined;
  try {
    let clock=Date.now();t.mock.method(Date,'now',()=>clock);
    const adapter=client.identity.provider.Interaction.adapter;
    const epoch=Math.floor(clock/1000);
    const payload={jti:'fixture-persisted-interaction',kind:'Interaction',iat:epoch,exp:epoch+600,prompt:{name:'login'},params:{client_id:'fixture-client'}};
    await adapter.upsert(payload.jti,payload,600);
    assert(Boolean(await client.identity.provider.Interaction.find(payload.jti)));
    const updated={...payload,prompt:{name:'consent'}};await adapter.upsert(payload.jti,updated,600);
    assert.equal((await adapter.find(payload.jti)).prompt.name,'consent');
    const invalid:any={};invalid.self=invalid;
    await assert.rejects(adapter.upsert(payload.jti,invalid,600));
    assert.equal((await adapter.find(payload.jti)).prompt.name,'consent','Failed serialization must roll back replacement');
    reopened=new Store(client.dbPath,Buffer.alloc(32,31));
    const second=await installIdentity(express(),{store:reopened,baseUrl:client.baseUrl,getPortalAccount:()=>owner});
    assert(Boolean(await second.provider.Interaction.find(payload.jti)),'Pending interaction must survive reopening SQLite and the provider');
    const another={...payload,jti:'fixture-another-interaction'};await adapter.upsert(another.jti,another,600);
    await second.provider.Interaction.adapter.destroy(another.jti);
    assert.equal(await adapter.find(another.jti),undefined);
    assert(Boolean(await adapter.find(payload.jti)));
    const sessions=client.identity.provider.Session.adapter;
    await sessions.upsert('fixture-session',{uid:'fixture-old-uid'},600);
    assert(Boolean(await sessions.findByUid('fixture-old-uid')));
    await sessions.upsert('fixture-session',{uid:'fixture-new-uid'},600);
    assert.equal(await sessions.findByUid('fixture-old-uid'),undefined);
    assert(Boolean(await sessions.findByUid('fixture-new-uid')));
    await sessions.destroy('fixture-session');assert.equal(await sessions.findByUid('fixture-new-uid'),undefined);
    clock+=600_001;
    assert.equal(await adapter.find(payload.jti),undefined);
    assert.equal(await second.provider.Interaction.find(payload.jti),undefined);
  } finally {reopened?.close();await client.close();}
});

test('interactionFinished failures are distinguished from the initial interactionDetails lookup',async(t)=>{
  const client=await harness();
  try {
    const {response,body:registered}=await register(client,'client_secret_post');assert.equal(response.status,201);
    let pendingUid:string|undefined;
    const save=client.identity.provider.Grant.prototype.save;
    t.mock.method(client.identity.provider.Grant.prototype,'save',async function(this:any,...args:any[]){
      const grantId=await save.apply(this,args);
      assert(pendingUid);await client.identity.provider.Interaction.adapter.destroy(pendingUid);
      return grantId;
    });
    const request=async(path:string,init:RequestInit={})=>{
      const url=new URL(path,client.baseUrl);
      if(url.pathname.startsWith('/interaction/'))pendingUid=url.pathname.split('/').at(-1);
      return client.request(path,init);
    };
    await assert.rejects(authorizationCode({...client,request},registered.client_id,googleRedirects[0],{state:'finish-fault-injection'}));
    assert.deepEqual(client.diagnostics,[{route:'/interaction/:uid',method:'POST',error:{name:'SessionNotFound',status:400,message:'interactionFinished: interaction session not found; cookie UID matches route'}}]);
  } finally {await client.close();}
});

test('a browser consent form remains valid after reopening the encrypted store and OAuth provider',async()=>{
  const client=await harness({https:true});
  let reopened:Store|undefined;
  try {
    const {response,body:registered}=await register(client,'client_secret_post');assert.equal(response.status,201);
    const params=new URLSearchParams({client_id:registered.client_id,redirect_uri:googleRedirects[0],response_type:'code',scope:'mcp profile:read offline_access',resource:resourceFor(client.baseUrl),state:'restart-browser-flow'});
    const redirect=await client.request(`/oidc/auth?${params}`);assert.equal(redirect.status,303);
    let current=new URL(redirect.headers.get('location')!,client.baseUrl);
    const page=await client.request(current.toString());assert.equal(page.status,200);
    let csrf=(await page.text()).match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];assert(csrf);
    reopened=new Store(client.dbPath,Buffer.alloc(32,31));
    const replacement=express();replacement.set('trust proxy',1);
    const reloaded=await installIdentity(replacement,{store:reopened,baseUrl:client.baseUrl,getPortalAccount:()=>owner});
    client.replaceApp(replacement);
    let code:string|undefined;
    for(let step=0;step<8;step++) {
      const approved=await client.request(current.toString(),{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:client.baseUrl},body:new URLSearchParams({csrf,decision:'approve'})});
      assert.equal(approved.status,303,'Pre-restart form and signed cookie must still be valid');
      current=new URL(approved.headers.get('location')!,current);
      const resumed=await client.request(current.toString());
      if(resumed.status===200){const destination=handoffTarget(await resumed.text());assert(destination);current=new URL(destination);assert.equal(current.searchParams.get('state'),'restart-browser-flow');code=current.searchParams.get('code')??undefined;break;}
      assert.equal(resumed.status,303);
      current=new URL(resumed.headers.get('location')!,current);
      if(current.origin!==client.baseUrl) {assert.equal(current.searchParams.get('state'),'restart-browser-flow');code=current.searchParams.get('code')??undefined;break;}
      const consent=await client.request(current.toString());assert.equal(consent.status,200);
      csrf=(await consent.text()).match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];assert(csrf);
    }
    assert(code);
    const exchanged=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0]});
    assert.equal(exchanged.response.status,200);
    assert(Boolean(await reloaded.provider.AccessToken.find(exchanged.body.access_token)));
    const refreshed=await tokenRequest(client,{grant_type:'refresh_token',client_id:registered.client_id,client_secret:registered.client_secret,refresh_token:exchanged.body.refresh_token});
    assert.equal(refreshed.response.status,200);
  } finally {await client.close();reopened?.close();}
});

async function register(client:Harness,authMethod:'none'|'client_secret_post') {
  const response=await client.request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
    client_name:'Google',
    token_endpoint_auth_method:authMethod,
    grant_types:['authorization_code','refresh_token'],
    response_types:['code'],
    redirect_uris:googleRedirects,
    scope:'mcp profile:read offline_access',
  })});
  return {response,body:await response.json() as Record<string,any>};
}

async function authorizationCode(client:Pick<Harness,'request'|'baseUrl'>,clientId:string,redirectUri:string,options:{state:string;challenge?:string;method?:string;scope?:string;login?:(url:URL,response:Response)=>Promise<URL>}):Promise<string> {
  const params=new URLSearchParams({client_id:clientId,redirect_uri:redirectUri,response_type:'code',scope:options.scope??'mcp profile:read offline_access',resource:resourceFor(client.baseUrl),state:options.state});
  if(options.challenge) {params.set('code_challenge',options.challenge);params.set('code_challenge_method',options.method??'S256');}
  const callbackCode=(url:URL) => {
    assert.equal(url.toString().startsWith(`${redirectUri}?`),true,'OAuth callback must exactly match the registered URI');
    assert.equal(url.searchParams.get('state'),options.state);
    const oauthError=url.searchParams.get('error');
    if(oauthError)throw Object.assign(new Error('OAuth authorization was rejected'),{oauthError});
    const code=url.searchParams.get('code');
    assert(code,'OAuth callback must contain an authorization code');
    return code;
  };
  let current=new URL(`/oidc/auth?${params}`,client.baseUrl);
  for(let step=0;step<12;step++) {
    const response=await client.request(current.toString());
    if(response.status>=300&&response.status<400) {
      const location=response.headers.get('location');
      assert(location,'OAuth redirect must have a Location header');
      current=new URL(location,current);
      if(current.origin!==client.baseUrl) {
        return callbackCode(current);
      }
      continue;
    }
    if(current.pathname==='/login'&&options.login) {current=await options.login(current,response);continue;}
    const html=await response.text();
    const destination=handoffTarget(html);
    if(destination)return callbackCode(new URL(destination,current));
    const csrf=html.match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];
    if(!csrf) {
      let oauthError:string|undefined;
      try {oauthError=(JSON.parse(html) as Record<string,unknown>).error as string|undefined;} catch {}
      if(oauthError)throw Object.assign(new Error('OAuth authorization was rejected'),{oauthError,status:response.status});
      assert.fail(`Expected the existing login/consent page, got HTTP ${response.status}`);
    }
    const approved=await client.request(current.toString(),{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:client.baseUrl},body:new URLSearchParams({csrf,decision:'approve'})});
    assert(approved.status>=300&&approved.status<400,`Consent form returned HTTP ${approved.status}`);
    const location=approved.headers.get('location');
    assert(location,'Consent form response must redirect');
    current=new URL(location,current);
    if(current.origin!==client.baseUrl) {
      return callbackCode(current);
    }
  }
  assert.fail('OAuth authorization did not reach the callback');
}

async function tokenRequest(client:Pick<Harness,'request'>,fields:Record<string,string>) {
  const response=await client.request('/oidc/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(fields)});
  return {response,body:await response.json() as Record<string,any>};
}

test('Gemini confidential and existing public clients register with truthful discovery metadata',async()=>{
  const client=await harness();
  try {
    const discoveryResponse=await client.request('/oidc/.well-known/openid-configuration');
    assert.equal(discoveryResponse.status,200);
    const discovery=await discoveryResponse.json() as Record<string,any>;
    assert.deepEqual(discovery.token_endpoint_auth_methods_supported,['client_secret_post','none']);
    assert.deepEqual(discovery.code_challenge_methods_supported,['S256']);

    const confidential=await register(client,'client_secret_post');
    assert.equal(confidential.response.status,201);
    assert.equal(confidential.body.client_name,'Google');
    assert.equal(confidential.body.token_endpoint_auth_method,'client_secret_post');
    assert.equal(typeof confidential.body.client_id,'string');
    assert.equal(typeof confidential.body.client_secret,'string');
    assert(confidential.body.client_secret.length>=32);
    assert.deepEqual(confidential.body.grant_types,['authorization_code','refresh_token']);
    assert.deepEqual(confidential.body.redirect_uris,googleRedirects);

    const publicClient=await register(client,'none');
    assert.equal(publicClient.response.status,201);
    assert.equal(publicClient.body.token_endpoint_auth_method,'none');
    assert.equal(Object.hasOwn(publicClient.body,'client_secret'),false);

    const unsupported=await client.request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'Unsupported',token_endpoint_auth_method:'client_secret_basic',grant_types:['authorization_code'],response_types:['code'],redirect_uris:[googleRedirects[0]]})});
    assert.equal(unsupported.status,400);
    const rejected=await unsupported.json() as Record<string,any>;
    assert.equal(rejected.error,'invalid_client_metadata');

    const unsafeRedirect=await client.request('/oidc/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'Unsafe',token_endpoint_auth_method:'client_secret_post',grant_types:['authorization_code'],response_types:['code'],redirect_uris:['http://untrusted.example/callback']})});
    assert.equal(unsafeRedirect.status,400);
  } finally {await client.close();}
});

test('confidential consent uses browser cookie paths through the HTTPS proxy',async()=>{
  const client=await harness({https:true});
  try {
    const {response,body:registered}=await register(client,'client_secret_post');
    assert.equal(response.status,201);
    const code=await authorizationCode(client,registered.client_id,googleRedirects[0],{state:'browser-path-aware'});
    const exchanged=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0]});
    assert.equal(exchanged.response.status,200);
  } finally {await client.close();}
});

test('confidential Gemini authorization exchanges once, rejects a bad secret, refreshes, and stays account/resource bound',async()=>{
  const client=await harness();
  try {
    const {response:registration,body:registered}=await register(client,'client_secret_post');
    assert.equal(registration.status,201,'confidential registration must succeed before token lifecycle');
    const code=await authorizationCode(client,registered.client_id,googleRedirects[0],{state:'gemini-state-fixture'});
    const wrong=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:'incorrect-fixture-secret',code,redirect_uri:googleRedirects[0]});
    assert.equal(wrong.response.status,401);
    assert.equal(wrong.body.error,'invalid_client');
    assert.equal(JSON.stringify(wrong.body).includes('incorrect-fixture-secret'),false);

    const exchanged=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0]});
    assert.equal(exchanged.response.status,200);
    assert.equal(typeof exchanged.body.access_token,'string');
    assert.equal(typeof exchanged.body.refresh_token,'string');
    assert.equal(exchanged.body.token_type,'Bearer');
    assert(exchanged.body.expires_in>0&&exchanged.body.expires_in<=900);
    const access=await client.identity.provider.AccessToken.find(exchanged.body.access_token);
    assert.equal(access.accountId,owner);
    assert.equal(access.aud,resourceFor(client.baseUrl));
    assert(access.scopes.has('mcp'));
    assert(access.scopes.has('profile:read'));
    assert(access.exp>Date.now()/1000);
    assert(access.exp<=Date.now()/1000+900+2);
    const refresh=await client.identity.provider.RefreshToken.find(exchanged.body.refresh_token);
    assert(refresh.exp>Date.now()/1000);
    assert(refresh.exp<=Date.now()/1000+604800+2);

    const mcpClient=new Client({name:'fixture-mcp-client',version:'1'});
    try {
      const transport=new StreamableHTTPClientTransport(new URL('/mcp',client.baseUrl),{requestInit:{headers:{authorization:`Bearer ${exchanged.body.access_token}`}}});
      await mcpClient.connect(transport);
      const read=await mcpClient.callTool({name:'get_connection_status',arguments:{}});
      const structured=read.structuredContent as Record<string,unknown>;
      assert.notEqual(read.isError,true);
      assert.equal(structured.status,'CONNECTED');
      assert.equal(structured.account_id,Number(owner));
    } finally {await mcpClient.close();}

    const refreshed=await tokenRequest(client,{grant_type:'refresh_token',client_id:registered.client_id,client_secret:registered.client_secret,refresh_token:exchanged.body.refresh_token});
    assert.equal(refreshed.response.status,200);
    assert.equal(typeof refreshed.body.access_token,'string');
    assert.equal(typeof refreshed.body.refresh_token,'string');
    const refreshedAccess=await client.identity.provider.AccessToken.find(refreshed.body.access_token);
    assert.equal(refreshedAccess.accountId,owner);
    assert.equal(refreshedAccess.aud,resourceFor(client.baseUrl));
    assert(refreshedAccess.scopes.has('mcp'));

    const replay=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code,redirect_uri:googleRedirects[0]});
    assert.equal(replay.response.status,400);
    assert.equal(replay.body.error,'invalid_grant');

    const verifier='Qpc7v6W3l9x2N8d5F1a4R0k3m6B9c2V7s5H8j1L4p0A';
    const challenge=(await import('node:crypto')).createHash('sha256').update(verifier).digest('base64url');
    const pkceCode=await authorizationCode(client,registered.client_id,googleRedirects[1],{state:'gemini-state-pkce-fixture',challenge});
    const pkceExchange=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code:pkceCode,redirect_uri:googleRedirects[1],code_verifier:verifier});
    assert.equal(pkceExchange.response.status,200);

    const racingCode=await authorizationCode(client,registered.client_id,googleRedirects[2],{state:'gemini-state-race-fixture'});
    const racingExchanges=await Promise.all([
      tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code:racingCode,redirect_uri:googleRedirects[2]}),
      tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,client_secret:registered.client_secret,code:racingCode,redirect_uri:googleRedirects[2]}),
    ]);
    assert.deepEqual(racingExchanges.map(exchange=>exchange.response.status).sort((a,b)=>a-b),[200,400]);
    assert.equal(racingExchanges.find(exchange=>exchange.response.status===400)?.body.error,'invalid_grant');

    const rawDb=new DatabaseSync(client.dbPath,{readOnly:true});
    try {
      const serialized=rawDb.prepare("SELECT group_concat(ns || k || v, '') AS raw FROM records").get() as {raw:string};
      assert.equal(serialized.raw.includes(registered.client_secret),false,'registered client secret must not appear in plaintext in SQLite');
      assert.equal(serialized.raw.includes(exchanged.body.access_token),false,'issued tokens must not appear in plaintext in SQLite');
      assert.equal(serialized.raw.includes(exchanged.body.refresh_token),false,'refresh tokens must not appear in plaintext in SQLite');
      assert.equal(serialized.raw.includes(code),false,'authorization codes must not appear in plaintext in SQLite');
    } finally {rawDb.close();}
  } finally {await client.close();}
});

test('public clients still require S256 PKCE and OAuth redirect matching remains exact',async()=>{
  const client=await harness();
  try {
    const {response:registration,body:registered}=await register(client,'none');
    assert.equal(registration.status,201);
    await assert.rejects(authorizationCode(client,registered.client_id,googleRedirects[0],{state:'missing-pkce'}),error=>{
      const value=error as {oauthError?:string};
      return value.oauthError==='invalid_request';
    });

    const verifier='gemini-public-pkce-verifier-7d8f2c4a-0123456789';
    const challenge=(await import('node:crypto')).createHash('sha256').update(verifier).digest('base64url');
    const code=await authorizationCode(client,registered.client_id,googleRedirects[0],{state:'public-state',challenge});
    const exchanged=await tokenRequest(client,{grant_type:'authorization_code',client_id:registered.client_id,code,redirect_uri:googleRedirects[0],code_verifier:verifier});
    assert.equal(exchanged.response.status,200,`public code exchange returned ${String(exchanged.body.error)}: ${String(exchanged.body.error_description)}`);
    assert.equal(exchanged.body.token_type,'Bearer');

    const mismatch=new URLSearchParams({client_id:registered.client_id,redirect_uri:`${googleRedirects[0]}/changed`,response_type:'code',scope:'mcp',resource:resourceFor(client.baseUrl),state:'redirect-mismatch',code_challenge:'plain-text',code_challenge_method:'plain'});
    const wrongRedirect=await client.request(`/oidc/auth?${mismatch}`);
    assert.equal(wrongRedirect.status,400);
    assert.match(wrongRedirect.headers.get('content-type')??'',/text\/html/);
    await wrongRedirect.text();

    await assert.rejects(authorizationCode(client,registered.client_id,googleRedirects[0],{state:'plain-pkce',challenge:'plain-text',method:'plain'}),error=>{
      return (error as {oauthError?:string}).oauthError==='invalid_request';
    });
  } finally {await client.close();}
});

test('consent cannot move to another connected account during one authorization',async()=>{
  const client=await harness();
  try {
    const {response:registration,body:registered}=await register(client,'client_secret_post');
    assert.equal(registration.status,201);
    const params=new URLSearchParams({client_id:registered.client_id,redirect_uri:googleRedirects[0],response_type:'code',scope:'mcp',resource:resourceFor(client.baseUrl),state:'account-binding'});
    const first=await client.request(`/oidc/auth?${params}`);
    assert(first.status>=300&&first.status<400);
    const interaction=new URL(first.headers.get('location')!,client.baseUrl);
    const page=await client.request(interaction.toString());
    const form=await page.text();
    const csrf=form.match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];
    assert(csrf);
    const login=await client.request(interaction.toString(),{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:client.baseUrl},body:new URLSearchParams({csrf,decision:'approve'})});
    const next=new URL(login.headers.get('location')!,interaction);
    assert(next.pathname.startsWith('/oidc/auth'));
    const consentRedirect=await client.request(next.toString());
    const consentUrl=new URL(consentRedirect.headers.get('location')!,client.baseUrl);
    assert(consentUrl.pathname.startsWith('/interaction/'));
    client.setAccount('other-account');
    const denied=await client.request(consentUrl.toString());
    assert.equal(denied.status,403);
  } finally {await client.close();}
});
