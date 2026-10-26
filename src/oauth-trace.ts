import {randomUUID} from 'node:crypto';
import express,{type Express,type RequestHandler,type Response} from 'express';

const requests=new WeakMap<object,{id:string;started:number}>();
const origins=new Map([
  ['https://oauth-redirect.googleusercontent.com','google_callback'],
  ['https://oauth-redirect-sandbox.googleusercontent.com','google_sandbox_callback'],
  ['https://oauth-redirect-test.googleusercontent.com','google_test_callback'],
  ['https://gemini.google.com','gemini'],
  ['https://accounts.google.com','google_accounts'],
]);
export const oauthTraceEnabled=()=>Date.now()<Number(process.env.OAUTH_TRACE_UNTIL);
const originClass=(value:unknown,baseUrl?:string)=>{
  if(typeof value!=='string')return 'absent';
  try {const origin=new URL(value,baseUrl).origin;return origin===baseUrl?'same_origin':origins.get(origin)??'other';} catch {return 'other';}
};
const routeClass=(path:string)=>{
  if(/^\/interaction\/[^/]+\/?$/.test(path))return '/interaction/:uid';
  if(/^\/oidc\/auth\/[^/]+\/?$/.test(path))return '/oidc/auth/:uid';
  return ['/oidc/auth','/oidc/token','/oidc/reg','/oidc/diagnostics/csp','/login','/login/request','/login/verify','/mcp'].includes(path)?path:undefined;
};
const requestInfo=(req:object)=>{let value=requests.get(req);if(!value){value={id:randomUUID(),started:Date.now()};requests.set(req,value);}return value;};
const emit=(event:Record<string,unknown>)=>{if(oauthTraceEnabled())console.info(JSON.stringify(event));};
const methodClass=(method:string)=>method==='GET'||method==='POST'?method:'OTHER';
const clientClass=(client:any)=>client?.clientName==='Google'?'google':client?.clientAuthMethod==='none'?'public':client?'confidential':'unknown';
const grantClass=(grant:unknown)=>grant==='authorization_code'||grant==='refresh_token'?grant:'other';
const errorClass=(error:unknown)=>['invalid_client','invalid_grant','invalid_request','invalid_scope','invalid_target','unauthorized_client','unsupported_grant_type','server_error'].includes(String(error))?String(error):'other';
const errorReason=(error:any)=>{
  const reasons=new Map([
    ['authorization code not found','code_missing'],['authorization code is expired','code_expired'],
    ['authorization code already used','code_reused'],['authorization code redirect_uri mismatch','redirect_mismatch'],
    ['client mismatch','client_mismatch'],['code_verifier must be provided','pkce_missing'],
    ['code_verifier does not match code_challenge','pkce_mismatch'],['client authentication failed','client_authentication_failed'],
  ]);
  return reasons.get(error?.error_detail)??reasons.get(error?.error_description)??'redacted';
};

/** No request bodies/headers, raw URLs, identifiers or arbitrary errors enter logs. */
export const oauthHttpTrace=(baseUrl:string):RequestHandler=>(req,res,next)=>{
  const route=routeClass(req.path);
  if(!oauthTraceEnabled()||!route){next();return;}
  const info=requestInfo(req);
  res.setHeader('X-OAuth-Diagnostic-Id',info.id);
  res.once('finish',()=>{
    const location=res.getHeader('Location');let target:URL|undefined;
    if(typeof location==='string')try{target=new URL(location,baseUrl);}catch{}
    const coop=res.getHeader('Cross-Origin-Opener-Policy');
    emit({event:'oauth_http',request_id:info.id,route,method:methodClass(req.method),status:res.statusCode,duration_ms:Date.now()-info.started,
      redirect_origin:originClass(typeof location==='string'?location:undefined,baseUrl),
      code_present:!!target&&(target.searchParams.has('code')||new URLSearchParams(target.hash.slice(1)).has('code')),
      state_present:!!target&&(target.searchParams.has('state')||new URLSearchParams(target.hash.slice(1)).has('state')),
      coop:['unsafe-none','same-origin','same-origin-allow-popups'].includes(String(coop))?coop:'other'});
  });
  next();
};

/** Time-limited protocol metadata only. Bodies are bounded in memory and never emitted. */
export const mcpProtocolTrace=(toolNames:readonly string[]):RequestHandler=>(req,res,next)=>{
  if(!oauthTraceEnabled()){next();return;}
  const info=requestInfo(req),body=req.body;
  const rpcMethod=['initialize','notifications/initialized','tools/list','tools/call','ping','resources/list','prompts/list'].includes(body?.method)?body.method:'other';
  const tool=body?.method==='tools/call'?(toolNames.includes(body?.params?.name)?body.params.name:'other'):undefined;
  const metadata={request_id:info.id,route:'/mcp',rpc_method:rpcMethod,...(tool?{tool}:{})};
  emit({event:'mcp_rpc_request',...metadata});
  let chunks:Buffer[]=[],size=0,truncated=false;
  const capture=(chunk:unknown,encoding:unknown)=>{
    if(truncated||chunk===undefined||chunk===null)return;
    try {
      const buffer=typeof chunk==='string'?Buffer.from(chunk,typeof encoding==='string'?encoding as BufferEncoding:'utf8'):Buffer.isBuffer(chunk)?chunk:chunk instanceof Uint8Array?Buffer.from(chunk):undefined;
      if(!buffer)return;
      size+=buffer.length;
      if(size>128*1024){chunks=[];truncated=true;return;}
      chunks.push(Buffer.from(buffer));
    } catch {chunks=[];truncated=true;}
  };
  const write=res.write,end=res.end;
  res.write=function(...args:any[]){capture(args[0],args[1]);return (write as any).apply(this,args);} as typeof res.write;
  res.end=function(...args:any[]){capture(args[0],args[1]);return (end as any).apply(this,args);} as typeof res.end;
  let logged=false;
  const finish=()=>{
    if(logged)return;logged=true;
    let response:any;
    if(!truncated)try{response=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{}
    chunks=[];
    const result=response?.result;
    const outcome=!res.writableFinished?'connection_closed':res.statusCode>=400?'http_error':response?.error?'protocol_error':result?.isError===true?'tool_error':result?'success':res.statusCode===202?'notification_accepted':'unclassified';
    const rpcError=[-32700,-32600,-32601,-32602,-32603].includes(response?.error?.code)?response.error.code:undefined;
    let errorCode:string|undefined;
    if(result?.isError===true)try{
      const candidate=JSON.parse(result.content?.find((item:any)=>item?.type==='text')?.text??'null')?.error;
      if(['REAUTH_REQUIRED','INSUFFICIENT_SCOPE','INVALID_INPUT','INTERNAL_ERROR','UPSTREAM_TIMEOUT','UPSTREAM_RATE_LIMITED','UPSTREAM_NETWORK_ERROR','UPSTREAM_SERVER_ERROR','UPSTREAM_VALIDATION_ERROR','UPSTREAM_MALFORMED_RESPONSE','POLICY_NOT_CONFIGURED'].includes(candidate))errorCode=candidate;
    }catch{}
    const client=(req as any).auth?.extra?.clientClass;
    emit({event:'mcp_rpc',...metadata,client_class:['google','public','confidential'].includes(client)?client:'unauthenticated',
      http_status:res.statusCode,duration_ms:Date.now()-info.started,outcome,response_truncated:truncated,
      ...(rpcError!==undefined?{rpc_error_code:rpcError}:{}),...(errorCode?{error_code:errorCode}:{}),
      ...(['CONNECTED','REAUTH_REQUIRED'].includes(result?.structuredContent?.status)?{connection_status:result.structuredContent.status}:{})});
  };
  res.once('finish',finish);res.once('close',finish);
  next();
};

export function addOAuthCspReporting(res:Response){
  if(!oauthTraceEnabled())return;
  const policy=res.getHeader('Content-Security-Policy');
  if(typeof policy!=='string')return;
  res.setHeader('Content-Security-Policy',policy.split(';').map(x=>x.trim()).filter(x=>x&&!/^report-uri(?:\s|$)/i.test(x)).concat('report-uri /oidc/diagnostics/csp').join(';'));
}

export function traceGoogleHandoff(req:object,callback:string){
  if(oauthTraceEnabled())emit({event:'oauth_handoff',request_id:requestInfo(req).id,route:'/oidc/auth/:uid',callback_origin:originClass(callback),navigation:'document'});
}

export function sanitizeOAuthCspReport(value:unknown,baseUrl:string){
  const input=value as any;
  const report=input?.['csp-report']??(input?.type==='csp-violation'?input.body:undefined);
  if(!report||typeof report!=='object')return undefined;
  const directive=report['effective-directive']??report.effectiveDirective??report['violated-directive'];
  const document=report['document-uri']??report.documentURL;
  let route:string|undefined;try{const url=new URL(document);if(url.origin!==baseUrl)return undefined;route=routeClass(url.pathname);}catch{return undefined;}
  if(!route)return undefined;
  return {event:'oauth_csp_violation',route,directive:['form-action','connect-src','script-src','frame-ancestors','default-src'].includes(directive)?directive:'other',
    blocked_origin:originClass(report['blocked-uri']??report.blockedURL,baseUrl),
    disposition:report.disposition==='enforce'?'enforce':report.disposition==='report'?'report':'unknown'};
}

export function installOAuthTrace(app:Express,provider:any,baseUrl:string){
  app.post('/oidc/diagnostics/csp',((req,res,next)=>{
    if(!oauthTraceEnabled()){res.status(204).end();return;}next();
  }) as RequestHandler,express.json({type:['application/csp-report','application/reports+json','application/json'],limit:'8kb'}),(req,res)=>{
    const reports=Array.isArray(req.body)?req.body.slice(0,4):[req.body];
    for(const report of reports){const sanitized=sanitizeOAuthCspReport(report,baseUrl);if(sanitized)emit(sanitized);}
    res.status(204).end();
  });
  // Importing no generic parser ahead of oidc-provider keeps its token body intact.
  provider.on('authorization.success',(ctx:any,out:any)=>{
    if(!oauthTraceEnabled())return;
    const params=ctx.oidc.params,client=ctx.oidc.client;
    emit({event:'oauth_authorization_result',request_id:requestInfo(ctx.req).id,client_class:clientClass(client),
      callback_origin:originClass(params.redirect_uri,baseUrl),callback_registered:!!client?.redirectUris?.includes(params.redirect_uri),
      response_mode:['query','fragment','form_post'].includes(ctx.oidc.responseMode)?ctx.oidc.responseMode:'other',
      code_issued:typeof out?.code==='string',state_present:typeof params.state==='string',state_preserved:params.state===out?.state,
      issuer_matches:out?.iss===provider.issuer,pkce_s256:params.code_challenge_method==='S256'});
  });
  provider.on('grant.success',(ctx:any)=>{
    if(!oauthTraceEnabled())return;
    emit({event:'oauth_token_result',request_id:requestInfo(ctx.req).id,client_class:clientClass(ctx.oidc.client),grant_type:grantClass(ctx.oidc.params?.grant_type),
      outcome:'success',access_issued:typeof ctx.body?.access_token==='string',refresh_issued:typeof ctx.body?.refresh_token==='string'});
  });
  provider.on('grant.error',(ctx:any,error:any)=>{
    if(!oauthTraceEnabled())return;
    emit({event:'oauth_token_result',request_id:requestInfo(ctx.req).id,client_class:clientClass(ctx.oidc.client),grant_type:grantClass(ctx.oidc.params?.grant_type),
      outcome:'error',error:errorClass(error?.error),reason:errorReason(error),status:Number.isInteger(error?.status)?error.status:500});
  });
}
