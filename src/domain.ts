import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Store } from './store.js';
import { KarlancerError, type RequestContext, type ResponseValidation } from './karlancer.js';
import { toolDefinitions, professionalProfileShape } from './tool-catalog.js';
import { fieldControls, isAiField, parseAiFields, type DelegatableKey } from './field-controls.js';

export class DomainError extends Error {
  constructor(public readonly code: string, message: string, public readonly requestId?: string) { super(message); this.name = 'DomainError'; }
}
export function normalizeToman(value: unknown): number {
  let amount = value;
  if (typeof amount === 'string') {
    amount = amount.trim().replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776)).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632));
    amount = (amount as string).replace(/\s*تومان$/, '').trim();
    if (!/^(?:\d+|\d{1,3}(?:[,٬]\d{3})+)$/.test(amount as string)) throw new DomainError('INVALID_CURRENCY', 'Amount must be an unambiguous integer in toman.');
    amount = Number((amount as string).replace(/[,٬]/g, ''));
  }
  if (typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount < 0) throw new DomainError('INVALID_CURRENCY', 'Amount must be a nonnegative safe integer in toman.');
  return amount;
}

export const policySchema = z.object({
  version:z.number().int().positive(),proposalsEnabled:z.boolean(),repliesEnabled:z.boolean(),
  minNetIncome:z.number().int().nonnegative().safe(),maxDurationDays:z.number().int().min(1).max(365),
  dailyMaxProposals:z.number().int().nonnegative(),dailyMaxTokens:z.number().int().nonnegative(),
  dailyMaxStatistics:z.number().int().nonnegative(),cashPremiumLimit:z.literal(0),allowIncludedPromotions:z.boolean(),
  aiFields:z.custom<DelegatableKey[]>(value=>{try{parseAiFields(value);return true;}catch{return false;}},'Unsupported AI field selection.').optional(),
}).strict();
export type FinancialPolicy = z.infer<typeof policySchema>;
/** Apply each owner's delegation independently; never lift real upstream limits. */
function effectivePolicy(policy:FinancialPolicy):FinancialPolicy {
  const effective={...policy};
  if(isAiField(policy,'minNetIncome'))effective.minNetIncome=0;
  for(const field of ['maxDurationDays','dailyMaxProposals','dailyMaxTokens','dailyMaxStatistics'] as const) {
    if(isAiField(policy,field))effective[field]=Number.MAX_SAFE_INTEGER;
  }
  for(const field of ['proposalsEnabled','repliesEnabled','allowIncludedPromotions'] as const) {
    if(isAiField(policy,field))effective[field]=true;
  }
  return effective;
}
export type ProfessionalProfile = z.infer<ReturnType<typeof professionalSchema>> & {version:number};
const professionalSchema = () => z.object(professionalProfileShape).strict();
interface Client {
  getProfile():Promise<any>;searchProjects(input:any):Promise<any>;getProject(ref:any):Promise<any>;getPlans(context?:any):Promise<any>;
  listProposals(page?:number,status?:string):Promise<any>;getProposal(id:any):Promise<any>;
  listConversations(page?:number,search?:string,unreadOnly?:boolean):Promise<any>;getMessages(room:any,page?:number):Promise<any>;
  submitBid(body:any):Promise<any>;updateBid(body:any):Promise<any>;sendMessage(body:any):Promise<any>;markRead(room:any):Promise<any>;competitionStatistics(project:any):Promise<any>;
}
export interface DomainTelemetryEvent {
  event: 'mcp_tool_error';
  tool: string;
  request_id: string;
  request_path: 'domain';
  http_status: number | null;
  duration_ms: number;
  response_validation: ResponseValidation;
  error_kind: string;
}
interface Options {store:Store;clientFor:(tenantId:string, context?:RequestContext)=>Client;clock?:()=>number;logger?:(event:DomainTelemetryEvent)=>void;}
type Kind = 'proposal'|'proposal_update'|'reply';
type State = 'SUBMITTING'|'CONFIRMED'|'NEEDS_PAYMENT'|'REAUTH_REQUIRED'|'REJECTED'|'UNKNOWN';
interface Draft {id:string;tenant:string;kind:Kind;createdAt:number;expiresAt:number;profileHash:string;policyHash:string;content:any;baseline:any;estimate:any;needsOwnerDecision?:boolean;operationId?:string;}
interface Operation {operation_id:string;draft_id:string;kind:Kind;status:State;created_at:number;updated_at:number;requestHash:string;remote_id?:string;error_code?:string;}
const hash = (v:unknown) => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const fail = (code:string,message:string):never => {throw new DomainError(code,message);};
const sameId = (a:any,b:any) => a != null && b != null && String(a)===String(b);
const projectId = (v:any) => v?.project_id ?? v?.project?.id;
const ownerId = (v:any) => v?.user_id ?? v?.freelancer_id ?? v?.user?.id;
const numericId = (v:any):number => { const n=Number(v); if (!Number.isSafeInteger(n)||n<1) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The upstream resource identifier is unsupported.'); return n; };
const count = (v:any):number => {const n=typeof v==='string'&&/^\d+$/.test(v)?Number(v):v;if(typeof n!=='number'||!Number.isSafeInteger(n)||n<0) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','An authoritative quota value is missing or invalid.');return n;};
/** Private contact and credential fields occur even in nested public project users. */
export function sanitizeToolOutput(value:any):any {
  if(Array.isArray(value))return value.map(sanitizeToolOutput);
  if(!value||typeof value!=='object')return value;
  const clean:Record<string,any>={};
  for(const [key,item] of Object.entries(value)) {
    const normalized=key.toLowerCase().replace(/[^a-z0-9]/g,'');
    const projectCredit=key==='token'&&typeof item==='number'&&Number.isSafeInteger(item)&&item>=0&&value.min_budget!==undefined&&value.id!==undefined;
    const quota=['tokens','availabletokens','dailymaxtokens','tokencost'].includes(normalized)&&typeof item==='number'&&Number.isSafeInteger(item)&&item>=0;
    if(!projectCredit&&!quota&&/token|password|secret|cookie|authorization|otp|verifycode|verificationcode|invitecode|email|phone|mobile|bank|iban|cardnumber|nationalid/.test(normalized))continue;
    if(['__proto__','constructor','prototype'].includes(key))continue;
    clean[key]=sanitizeToolOutput(item);
  }
  return clean;
}

export class DomainService {
  private readonly store:Store;
  private readonly clientFor:(tenantId:string, context?:RequestContext)=>Client;
  private readonly clock:()=>number;
  private readonly logger:(event:DomainTelemetryEvent)=>void;
  constructor(options:Options) {this.store=options.store;this.clientFor=options.clientFor;this.clock=options.clock??Date.now;this.logger=options.logger??(event=>console.info(JSON.stringify(event)));}
  private ns(tenant:string,section:string) {return `${section}:${tenant}`;}
  private profile(tenant:string):ProfessionalProfile {return this.store.get<ProfessionalProfile>('profile',tenant)??{version:0};}
  private rawPolicy(tenant:string) {return this.store.get<any>('policy',tenant)??null;}
  private policyView(tenant:string) {
    const raw=this.rawPolicy(tenant),parsed=policySchema.safeParse(raw);
    return {financial_policy:raw,effective_financial_policy:parsed.success?effectivePolicy(parsed.data):null,field_controls:fieldControls(parsed.success?parsed.data.aiFields??[]:[])};
  }
  private policy(tenant:string,mode:'proposal'|'reply'|'statistics'):FinancialPolicy {
    const parsed=policySchema.safeParse(this.rawPolicy(tenant));
    const p=parsed.success?effectivePolicy(parsed.data):null;
    if(!p || (mode==='proposal'&&!p.proposalsEnabled) || (mode==='reply'&&!p.repliesEnabled) || (mode==='statistics'&&p.dailyMaxStatistics<1)) return fail('POLICY_NOT_CONFIGURED','Enable and complete the relevant policy in the authenticated human portal.');
    return p;
  }
  private projectReference(ref: unknown): string | number {
    if(typeof ref==='number'&&Number.isSafeInteger(ref)&&ref>0)return ref;
    if(typeof ref==='string'&&ref===ref.trim()&&ref.length>0&&ref.length<=200)return ref;
    return fail('INVALID_PROJECT_REFERENCE','Project reference must be a positive ID or a nonempty slug.');
  }
  private async connection(tenant:string, context?:RequestContext) {
    const session=this.store.unseal<any>(tenant,'karlancer');
    if(!session?.accountId) return fail('REAUTH_REQUIRED','Connect this tenant’s Karlancer account in the human portal.');
    const client=this.clientFor(tenant,context);const data=await client.getProfile();const user=data?.user??data?.profile??data;
    if(!sameId(user?.id,session.accountId)) return fail('REAUTH_REQUIRED','The connected account no longer matches the bound owner.');
    return {client,accountId:numericId(session.accountId),role:typeof user.role==='string'?user.role:undefined};
  }
  async execute(tenant:string,name:string,input:any={}):Promise<any> {
    const requestId=randomUUID(),startedAt=Date.now();
    try {return sanitizeToolOutput(await this.run(tenant,name,input,{tool:name,requestId}));}
    catch(error:any) {
      const translated=this.translateError(error,requestId);
      this.logger({event:'mcp_tool_error',tool:name,request_id:requestId,request_path:'domain',http_status:typeof error?.status==='number'?error.status:null,duration_ms:Date.now()-startedAt,response_validation:'not_attempted',error_kind:translated.code});
      throw translated;
    }
  }
  private translateError(error:any,requestId:string):DomainError {
    if(error instanceof DomainError)return new DomainError(error.code,error.message,requestId);
    const code=error instanceof KarlancerError?error.code:undefined;
    const mapped:Record<string,[string,string]>= {
      UNAUTHORIZED:['REAUTH_REQUIRED','Karlancer session authorization has expired.'],
      PAYMENT_REQUIRED:['NEEDS_PAYMENT','Karlancer requires payment; no purchase was performed.'],
      RATE_LIMITED:['UPSTREAM_RATE_LIMITED','Karlancer is temporarily rate-limiting this request.'],
      VALIDATION_ERROR:['UPSTREAM_VALIDATION_ERROR','Karlancer rejected the request validation.'],
      UPSTREAM_REQUEST_REJECTED:['UPSTREAM_REQUEST_REJECTED','Karlancer rejected this request.'],
      UPSTREAM_SERVER_ERROR:['UPSTREAM_SERVER_ERROR','Karlancer encountered an upstream server error.'],
      TIMEOUT:['UPSTREAM_TIMEOUT','Karlancer did not respond before the request deadline.'],
      NETWORK_ERROR:['UPSTREAM_NETWORK_ERROR','The connection to Karlancer failed before a response.'],
      MALFORMED_RESPONSE:['UPSTREAM_MALFORMED_RESPONSE','Karlancer returned an unsupported response.'],
      INVALID_PROJECT_REDIRECT:['UPSTREAM_PROJECT_RESOLUTION_ERROR','Karlancer could not safely resolve the project ID.'],
    };
    const selected=mapped[code??''];
    if(selected)return new DomainError(selected[0],selected[1],requestId);
    if(error?.status===401)return new DomainError('REAUTH_REQUIRED','Karlancer session authorization has expired.',requestId);
    if(error?.status===402)return new DomainError('NEEDS_PAYMENT','Karlancer requires payment; no purchase was performed.',requestId);
    if(typeof error?.status==='number'&&error.status>=500)return new DomainError('UPSTREAM_SERVER_ERROR','Karlancer encountered an upstream server error.',requestId);
    return new DomainError('INTERNAL_ERROR','The MCP service could not complete the request.',requestId);
  }
  private async run(tenant:string,name:string,input:any={},context?:RequestContext):Promise<any> {
    if(typeof tenant!=='string'||!tenant||tenant.length>200) return fail('UNAUTHORIZED','A trusted tenant identity is required.');
    const def=toolDefinitions.find(t=>t.name===name);if(!def) return fail('UNKNOWN_TOOL','Unknown tool.');
    const parsed=z.object(def.inputSchema).strict().safeParse(input??{});if(!parsed.success) return fail('INVALID_INPUT','Input does not match the supported tool schema.');
    const i:any=parsed.data;
    try {
      if(name==='get_profile') return {profile:this.profile(tenant),...this.policyView(tenant)};
      if(name==='update_profile') return this.store.withLock(this.ns(tenant,'writes'),async()=>{
        const policy=policySchema.safeParse(this.rawPolicy(tenant));
        if(Object.keys(i).some(field=>!policy.success||!isAiField(policy.data,field as DelegatableKey))) return fail('FIELD_MANAGED_BY_OWNER','Only profile fields delegated to AI in the authenticated human portal may be edited.');
        const existing=this.profile(tenant); const updated={...existing,...professionalSchema().parse(i),version:existing.version+1};
        if(updated.resumeUrl==='')delete updated.resumeUrl;
        this.store.put('profile',tenant,updated);return {profile:updated};
      });
      if(name==='get_operation_status') return this.store.withLock(this.ns(tenant,'writes'),async()=>this.publicOperation(this.operation(tenant,i.operation_id)));
      if(name==='get_connection_status') {
        try {const c=await this.connection(tenant,context);return {status:'CONNECTED',account_id:c.accountId,role:c.role};}
        catch(e:any) {if(e instanceof DomainError&&e.code==='REAUTH_REQUIRED'||e?.status===401) return {status:'REAUTH_REQUIRED'};throw e;}
      }
      if(['submit_proposal','submit_proposal_update','send_reply'].includes(name)) return await this.submit(tenant,name,i,context);
      const {client,accountId}=await this.connection(tenant,context);
      switch(name) {
        case 'search_projects': return {projects:await client.searchProjects({...i,...(i.minPrice!==undefined?{minPrice:normalizeToman(i.minPrice)}:{}),...(i.maxPrice!==undefined?{maxPrice:normalizeToman(i.maxPrice)}:{})}),external_content_untrusted:true};
        case 'get_project': return {project:await client.getProject(this.projectReference(i.project_ref)),profile:this.profile(tenant),...this.policyView(tenant),external_content_untrusted:true};
        case 'get_plan_usage': {const project=i.project_ref!==undefined?await client.getProject(this.projectReference(i.project_ref)):undefined;return {usage:await this.plans(client,project),daily_usage:this.usage(tenant),cash_purchases_enabled:false};}
        case 'list_proposals':return {proposals:await client.listProposals(i.page,i.status),external_content_untrusted:true};
        case 'get_proposal':return {proposal:await this.ownedProposal(client,accountId,i.proposal_id),external_content_untrusted:true};
        case 'list_conversations':return {conversations:await client.listConversations(i.page,i.search,i.unread_only),external_content_untrusted:true};
        case 'get_messages':await this.ownedRoom(client,i.room_id);return {messages:await client.getMessages(numericId(i.room_id),i.page),read_status_side_effect:'unknown_may_mark_read',external_content_untrusted:true};
        case 'prepare_proposal':return this.prepareProposal(tenant,client,accountId,i);
        case 'prepare_proposal_update':return this.prepareProposal(tenant,client,accountId,i,true);
        case 'prepare_reply':return this.prepareReply(tenant,client,accountId,i);
        case 'mark_conversation_read':return this.store.withLock(this.ns(tenant,'writes'),async()=>{this.policy(tenant,'reply');await this.ownedRoom(client,i.room_id);try{await client.markRead(numericId(i.room_id));return {status:'CONFIRMED',effect:'read_marker_request_accepted'};}catch(e:any){return {status:e?.status===401?'REAUTH_REQUIRED':'UNKNOWN'};}});
        case 'get_competition_statistics':return this.statistics(tenant,client,i.project_id);
        default:return fail('UNKNOWN_TOOL','Unknown tool.');
      }
    } catch(error:any) {
      if(error instanceof DomainError) throw error;
      throw error;
    }
  }
  private async allPages(fetchPage:(page:number)=>Promise<any>):Promise<any[]> {
    const all:any[]=[];
    for(let page=1;page<=100;page++) {
      const result=await fetchPage(page);
      if(Array.isArray(result)) {if(page!==1) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Unsupported pagination.');return result;}
      const rows=Array.isArray(result?.data)?result.data:Array.isArray(result?.items)?result.items:undefined;
      if(!rows) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The upstream account list structure is unsupported.');all.push(...rows);
      if(result.last_page!==undefined) {if(count(result.last_page)<=page) return all;}
      else if(result.next_page_url===null || rows.length===0) return all;
      else return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Account ownership pagination cannot be verified.');
    }
    return fail('OWNERSHIP_UNVERIFIED','The account list exceeds the supported verification limit.');
  }
  private async ownedProposal(client:Client,accountId:number,id:any) {
    const rows=await this.allPages(p=>client.listProposals(p));
    if(!rows.some(r=>sameId(r.id,id))) return fail('NOT_FOUND','No owned proposal was found.');
    const bid=await client.getProposal(numericId(id));
    if(!sameId(bid?.id,id)||(ownerId(bid)!==undefined&&!sameId(ownerId(bid),accountId))) return fail('NOT_FOUND','No owned proposal was found.');return bid;
  }
  private async ownedRoom(client:Client,id:any) {
    const rooms=await this.allPages(p=>client.listConversations(p));const room=rooms.find(r=>sameId(r.id,id));
    if(!room) return fail('NOT_FOUND','No owned conversation was found.');return room;
  }
  private roomWritable(room:any) {
    if(room.is_closed===true||room.is_open===false||room.is_open===0||room.employer_is_open===false||room.employer_is_open===0) return fail('ROOM_CLOSED','This conversation is closed.');
    if(room.is_locked===true||room.is_locked===1||room.locked===true||room.am_locked===true||room.am_locked===1||room.user_locked===true||room.peer_locked===true) return fail('ROOM_LOCKED','This conversation is locked.');
    if(room.is_system===true||room.system===true||sameId(room.id,0)||sameId(room.user_id,0)) return fail('SYSTEM_ROOM','Automatic replies to system conversations are not supported.');
    const normalized=room.is_closed===false&&(room.is_locked===false||room.locked===false)&&(room.is_system===false||room.system===false);
    const observed=(room.is_open===true||room.is_open===1)&&(room.employer_is_open===true||room.employer_is_open===1)&&(room.am_locked===0||room.am_locked===false)&&room.is_locked===false&&Number(room.user_id)>0;
    if(!normalized&&!observed) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Conversation permission and system status cannot be verified.');
  }
  private async plans(client:Client,project?:any) {
    let context:any;
    const employer=project?.employer_id??project?.employer?.id??project?.user_id;
    const skills=project?.skills;
    if(employer!==undefined && Array.isArray(skills)) context={employerId:numericId(employer),projectId:numericId(project.id),skillIds:skills.map((s:any)=>numericId(s?.id??s))};
    return client.getPlans(context);
  }
  private terms(project:any) {
    if(!project?.id) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Project identity is missing.');
    if(project.is_expired===true||project.is_expired===1||!['pending','open'].includes(project.status)) return fail('PROJECT_NOT_OPEN','The project is not verified as accepting proposals.');
    const minBudget=normalizeToman(project.min_budget);
    const maxBudget=project.max_budget===undefined||project.max_budget===null||project.max_budget===''?undefined:normalizeToman(project.max_budget);
    if(maxBudget!==undefined&&maxBudget<minBudget)return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Project budget limits are inconsistent.');
    return {project_id:numericId(project.id),status:project.status,min_budget:minBudget,...(maxBudget===undefined?{}:{max_budget:maxBudget}),token_cost:count(project.bid_token_cost??project.token)};
  }
  private milestones(input:any[]) {
    const rows=input.map(m=>{let duration:number;try{duration=normalizeToman(m.duration);}catch{return fail('INVALID_DURATION','Milestone duration must be an integer number of days.');}
      const budget=normalizeToman(m.budget);if(duration<1||duration>365)return fail('INVALID_DURATION','Milestone duration must be between 1 and 365 days.');if(budget<10000)return fail('INVALID_BUDGET','Each milestone must be at least 10,000 toman.');
      if(input.length>1&&(m.description??'').trim().length<6) return fail('INVALID_MILESTONE','Multiple milestones need descriptions of at least six characters.');return {description:m.description??'',duration,budget};});
    const total=rows.reduce((s,r)=>s+r.budget,0);if(!Number.isSafeInteger(total)) return fail('INVALID_CURRENCY','The total budget exceeds the supported integer range.');return rows;
  }
  private commission(plans:any) {
    const raw=plans?.commission_percent??plans?.commission??plans?.plans?.plan?.commission;
    const n=typeof raw==='string'&&/^\d+(?:\.\d+)?$/.test(raw)?Number(raw):raw;
    if(typeof n!=='number'||!Number.isFinite(n)||n<0||n>100) return fail('UPSTREAM_SCHEMA_UNSUPPORTED','A verified commission percentage is required.');return n;
  }
  private availableTokens(plans:any) {
    if(plans?.available_tokens!==undefined) return count(plans.available_tokens);
    const active=plans?.plans;
    if(!active||active.total_bid===undefined||active.used_bid===undefined)return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Verified remaining account credit is required.');
    const expires=Date.parse(active.expire_date);
    if(!Number.isFinite(expires))return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Account credit expiration cannot be verified.');
    if(expires<=this.clock())return 0;
    // bidplans can include the same credit pool. Only the primary verified pool is counted.
    return Math.max(0,count(active.total_bid)-count(active.used_bid));
  }
  private proposalChecks(content:any,project:any,plans:any,policy?:FinancialPolicy) {
    if(plans?.employer_blocked===true||plans?.employer_blocked===1)return fail('EMPLOYER_BLOCKED','The account is blocked from proposing to this employer.');
    const terms=this.terms(project);const total=content.milestones.reduce((s:number,m:any)=>s+m.budget,0);
    if(total<terms.min_budget)return fail('INVALID_BUDGET','Proposal total is below the project minimum.');
    if(terms.max_budget!==undefined&&total>terms.max_budget)return fail('BUDGET_CAP_EXCEEDED','Proposal total exceeds the verified project budget ceiling.');
    const duration=content.milestones.reduce((s:number,m:any)=>s+m.duration,0);const commission=this.commission(plans);const net=Math.floor(total*(100-commission)/100);
    if(policy&&duration>policy.maxDurationDays)return fail('DURATION_POLICY_EXCEEDED','The total duration exceeds the configured capacity.');
    if(policy&&net<policy.minNetIncome)return fail('NET_INCOME_TOO_LOW','The proposal does not meet the configured net income floor.');
    if(this.availableTokens(plans)<terms.token_cost)return fail('INSUFFICIENT_TOKENS','The account does not have sufficient included proposal credit.');
    for(const key of ['pin','highlight','multi']) if(content[`is_${key}`]) {
      if(!policy?.allowIncludedPromotions)return fail('PROMOTION_NOT_ALLOWED','This policy does not allow included promotions.');
      if(count(plans?.included_promotions?.[key])<1)return fail('PROMOTION_QUOTA_EXHAUSTED','A verified included promotion is unavailable; no purchase is permitted.');
    }
    return {budget_toman:total,duration_days:duration,commission_percent:commission,estimated_net_toman:net,tokens:terms.token_cost,cash_toman:0};
  }
  private preparedResult(d:Draft) {
    return {draft_id:d.id,status:'PREPARED',expires_at:new Date(d.expiresAt).toISOString(),content:d.content,estimate:d.estimate,needs_owner_decision:d.needsOwnerDecision===true};
  }
  private prepared(tenant:string,kind:Kind,content:any,baseline:any,estimate:any,needsOwnerDecision=false) {
    const profileHash=hash(this.profile(tenant)),policyHash=hash(this.rawPolicy(tenant));
    const fingerprint=hash({kind,profileHash,policyHash,content,baseline,needsOwnerDecision});
    return this.store.transaction(()=>{
      const index=this.ns(tenant,'draft-fingerprint'),drafts=this.ns(tenant,'draft'),existingId=this.store.get<string>(index,fingerprint);
      let existing=existingId?this.store.get<Draft>(drafts,existingId):undefined;
      if(!existing)existing=this.store.list<Draft>(drafts).map(row=>row.value).find(d=>hash({kind:d.kind,profileHash:d.profileHash,policyHash:d.policyHash,content:d.content,baseline:d.baseline,needsOwnerDecision:d.needsOwnerDecision===true})===fingerprint);
      if(existing&&existing.tenant===tenant&&existing.kind===kind&&existing.expiresAt>this.clock()&&!existing.operationId){this.store.put(index,fingerprint,existing.id);return this.preparedResult(existing);}
      const createdAt=this.clock(),d:Draft={id:randomUUID(),tenant,kind,createdAt,expiresAt:createdAt+30*60*1000,profileHash,policyHash,content,baseline,estimate,needsOwnerDecision};
      this.store.put(drafts,d.id,d);this.store.put(index,fingerprint,d.id);return this.preparedResult(d);
    });
  }
  private proposalEditable(bid:any) {
    if(bid?.can_edit===false || !(bid?.can_edit===true||bid?.status==='pending'))return fail('PROPOSAL_NOT_EDITABLE','The proposal is not verified as editable.');
  }
  private updateProjectReference(bid:any):string|number {
    const reference=bid?.project?.slug??bid?.project?.url;
    if(typeof reference==='string'&&reference) {
      const url=new URL(reference,'https://www.karlancer.com');
      if(!['www.karlancer.com','karlancer.com'].includes(url.hostname)||!['http:','https:'].includes(url.protocol))return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The owned proposal contains an unsupported project URL.');
      const parts=url.pathname.split('/').filter(Boolean);
      const slug=parts.length===1?parts[0]:parts.length===2&&parts[0]==='projects'?parts[1]:undefined;
      if(!slug)return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The project URL cannot be resolved to a supported slug.');return decodeURIComponent(slug);
    }
    const id=projectId(bid);if(id===undefined)return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The proposal project could not be verified.');return numericId(id);
  }
  private async prepareProposal(tenant:string,client:Client,accountId:number,i:any,update=false) {
    const bid=update?await this.ownedProposal(client,accountId,i.proposal_id):undefined;
    if(update)this.proposalEditable(bid);
    const ref=update?this.updateProjectReference(bid):this.projectReference(i.project_ref);if(ref===undefined)return fail('UPSTREAM_SCHEMA_UNSUPPORTED','The proposal project could not be verified.');
    const policy=this.policy(tenant,'proposal');
    const project=await client.getProject(ref);const plans=await this.plans(client,project);
    const profile=this.profile(tenant);let description=i.description;
    const links=[...new Set([profile.resumeUrl,...(profile.portfolioUrls??[])].filter((v):v is string=>!!v))];
    const missing=links.filter(link=>!description.includes(link));if(missing.length)description+=`\n\nرزومه و نمونه‌کار: ${missing.join('\n')}`;
    if(description.length>20000)return fail('INVALID_DESCRIPTION','Proposal description exceeds the supported length after portfolio links are added.');
    const content={project_id:numericId(project.id),description,milestones:this.milestones(i.milestones),is_pin:i.is_pin??false,is_highlight:i.is_highlight??false,is_multi:i.is_multi??false,...(update?{bid_id:numericId(i.proposal_id)}:{})};
    const estimate=this.proposalChecks(content,project,plans,policy);
    return this.prepared(tenant,update?'proposal_update':'proposal',content,{project_ref:ref,terms:this.terms(project),...(update?{bidHash:hash(bid)}:{})},estimate);
  }
  private messageRows(result:any) {const payload=result?.messages??result;const rows=Array.isArray(payload)?payload:payload?.data;if(!Array.isArray(rows))return fail('UPSTREAM_SCHEMA_UNSUPPORTED','Message pagination is unsupported.');return rows;}
  private async replyContext(client:Client,accountId:number,roomId:any,baseId?:any) {
    let room=await this.ownedRoom(client,roomId);this.roomWritable(room);
    const response=await client.getMessages(numericId(roomId),1);
    if(response?.room){if(!sameId(response.room.id,roomId))return fail('ROOM_RELATION_UNVERIFIED','The fresh conversation details do not match the owned room.');room={...room,...response.room};this.roomWritable(room);}
    const rows=this.messageRows(response);
    const relevant=rows.filter((m:any)=>m?.sender_id!==undefined).sort((a:any,b:any)=>{
      const at=Date.parse(a.created_at),bt=Date.parse(b.created_at);
      return Number.isFinite(at)&&Number.isFinite(bt)&&at!==bt?bt-at:numericId(b.id)-numericId(a.id);
    });
    if(!relevant.length)return fail('NO_INBOUND_MESSAGE','No verified inbound message exists on the newest page.');
    if(sameId(relevant[0].sender_id,accountId))return fail('ALREADY_REPLIED','The latest conversation message was sent by this account.');
    const inbound=relevant[0];if(baseId!==undefined&&!sameId(inbound.id,baseId))return fail('STALE_DRAFT','The reply must target the newest inbound message.');
    if(!sameId(inbound.receptor_id,accountId)||!sameId(inbound.room_id,roomId))return fail('ROOM_RELATION_UNVERIFIED','The inbound message does not establish the current account and room.');
    const peer=room.receptor_id??room.user_id;if(!sameId(peer,inbound.sender_id)||sameId(peer,accountId))return fail('ROOM_RELATION_UNVERIFIED','The conversation recipient cannot be verified.');
    const pid=projectId(room)??projectId(inbound);if(pid===undefined)return fail('ROOM_RELATION_UNVERIFIED','The conversation project is unknown.');
    if(projectId(inbound)!==undefined&&!sameId(projectId(inbound),pid))return fail('ROOM_RELATION_UNVERIFIED','The conversation project does not match its messages.');
    const bids=await this.allPages(p=>client.listProposals(p));const related=bids.find(b=>sameId(projectId(b),pid)&&(ownerId(b)===undefined||sameId(ownerId(b),accountId)));
    if(!related)return fail('ROOM_RELATION_UNVERIFIED','No owned proposal establishes the conversation project.');
    await this.ownedProposal(client,accountId,related.id);
    return {room,inbound,peer:numericId(peer),project:numericId(pid),fingerprint:hash({room,inbound})};
  }
  private async prepareReply(tenant:string,client:Client,accountId:number,i:any) {
    const c=await this.replyContext(client,accountId,i.room_id,i.base_message_id);
    return this.prepared(tenant,'reply',{room_id:numericId(i.room_id),receptor_id:c.peer,reply_id:numericId(i.base_message_id),message:i.message,file:''},{fingerprint:c.fingerprint,base_message_id:i.base_message_id,project_id:c.project},{cash_toman:0},i.kind==='commercial_terms'||i.needs_owner_decision===true);
  }
  private usage(tenant:string) {return this.store.get<any>(this.ns(tenant,'usage'),new Date(this.clock()).toISOString().slice(0,10))??{proposals:0,tokens:0,statistics:0};}
  private reserve(tenant:string,policy:FinancialPolicy,proposals:number,tokens:number,statistics=0) {
    const key=new Date(this.clock()).toISOString().slice(0,10),u=this.usage(tenant);
    if(u.proposals+proposals>policy.dailyMaxProposals||u.tokens+tokens>policy.dailyMaxTokens||u.statistics+statistics>policy.dailyMaxStatistics)return fail('DAILY_LIMIT_EXCEEDED','This operation exceeds the configured daily quota.');
    this.store.put(this.ns(tenant,'usage'),key,{proposals:u.proposals+proposals,tokens:u.tokens+tokens,statistics:u.statistics+statistics});
  }
  private operation(tenant:string,id:string):Operation {
    const op=this.store.get<Operation>(this.ns(tenant,'operation'),id);if(!op)return fail('NOT_FOUND','No operation exists for this tenant.');
    if(op.status==='SUBMITTING'){op.status='UNKNOWN';op.error_code='INTERRUPTED_WRITE';op.updated_at=this.clock();this.store.put(this.ns(tenant,'operation'),id,op);}return op;
  }
  private publicOperation(op:Operation) {const {requestHash,...result}=op;return result;}
  private async submit(tenant:string,name:string,i:any,context?:RequestContext) {
    return this.store.withLock(this.ns(tenant,'writes'),async()=>{
      const idemKey=hash(i.idempotency_key);const existing=this.store.get<string>(this.ns(tenant,'idempotency'),idemKey);
      const expectedKind:Kind=name==='send_reply'?'reply':name==='submit_proposal_update'?'proposal_update':'proposal';
      if(existing){const op=this.operation(tenant,existing);if(op.draft_id!==i.draft_id||op.kind!==expectedKind)return fail('IDEMPOTENCY_CONFLICT','This idempotency key is bound to another draft.');return this.publicOperation(op);}
      const draft=this.store.get<Draft>(this.ns(tenant,'draft'),i.draft_id);if(!draft||draft.tenant!==tenant)return fail('NOT_FOUND','No draft exists for this tenant.');
      if(draft.kind!==expectedKind)return fail('INVALID_DRAFT_TYPE','This tool cannot submit that draft kind.');
      if(draft.operationId)return fail('DRAFT_ALREADY_SUBMITTED','This draft already has an operation; inspect that result.');
      if(draft.expiresAt<=this.clock())return fail('DRAFT_EXPIRED','Prepare a fresh draft.');
      if(draft.profileHash!==hash(this.profile(tenant))||draft.policyHash!==hash(this.rawPolicy(tenant)))return fail('STALE_DRAFT','The professional profile or policy changed after preparation.');
      const policy=this.policy(tenant,draft.kind==='reply'?'reply':'proposal');
      if(draft.needsOwnerDecision)return fail('OWNER_DECISION_REQUIRED','This reply requires the owner’s decision in the human portal.');
      const {client,accountId}=await this.connection(tenant,context);let estimate=draft.estimate;
      if(draft.kind==='reply') {
        const context=await this.replyContext(client,accountId,draft.content.room_id,draft.baseline.base_message_id);
        if(context.fingerprint!==draft.baseline.fingerprint)return fail('STALE_DRAFT','The conversation context changed after preparation.');
      } else {
        const project=await client.getProject(draft.baseline.project_ref);if(hash(this.terms(project))!==hash(draft.baseline.terms))return fail('STALE_DRAFT','The project terms changed after preparation.');
        if(draft.kind==='proposal_update'){const bid=await this.ownedProposal(client,accountId,draft.content.bid_id);if(hash(bid)!==draft.baseline.bidHash)return fail('STALE_DRAFT','The proposal changed after preparation.');this.proposalEditable(bid);}
        estimate=this.proposalChecks(draft.content,project,await this.plans(client,project),policy);
      }
      const operation:Operation={operation_id:randomUUID(),draft_id:draft.id,kind:draft.kind,status:'SUBMITTING',created_at:this.clock(),updated_at:this.clock(),requestHash:hash(draft.content)};
      this.store.transaction(()=>{
        this.reserve(tenant,policy,draft.kind==='proposal'?1:0,draft.kind==='reply'?0:estimate.tokens);
        this.store.put(this.ns(tenant,'operation'),operation.operation_id,operation);
        this.store.put(this.ns(tenant,'idempotency'),idemKey,operation.operation_id);
        draft.operationId=operation.operation_id;this.store.put(this.ns(tenant,'draft'),draft.id,draft);
      });
      try {
        const result=draft.kind==='reply'?await client.sendMessage(draft.content):draft.kind==='proposal_update'?await client.updateBid({...draft.content,edit_cart_id:null}):await client.submitBid({...draft.content,bid_id:null,edit_cart_id:null});
        const id=result?.id??result?.bid?.id??result?.message?.id;
        if(id===undefined){operation.status='UNKNOWN';operation.error_code='UNVERIFIED_WRITE_RESULT';}
        else if(await this.confirm(client,accountId,draft,id)){operation.status='CONFIRMED';operation.remote_id=String(id);}
        else {operation.status='UNKNOWN';operation.error_code='WRITE_NOT_CONFIRMED';}
      } catch(error:any) {
        const status=error?.status;
        operation.status=status===402?'NEEDS_PAYMENT':status===401?'REAUTH_REQUIRED':status>=400&&status<500?'REJECTED':'UNKNOWN';
        operation.error_code=operation.status==='UNKNOWN'?'WRITE_DELIVERY_UNKNOWN':operation.status;
        if(status===401){try{await client.getProfile();}catch{/* A read-only recheck never replays a write. */}}
      }
      operation.updated_at=this.clock();this.store.put(this.ns(tenant,'operation'),operation.operation_id,operation);return this.publicOperation(operation);
    });
  }
  private async confirm(client:Client,accountId:number,draft:Draft,id:any) {
    if(draft.kind==='reply') {
      const rows=this.messageRows(await client.getMessages(draft.content.room_id,1));
      return rows.some((m:any)=>sameId(m.id,id)&&sameId(m.room_id,draft.content.room_id)&&sameId(m.sender_id,accountId)&&sameId(m.receptor_id,draft.content.receptor_id)&&sameId(m.reply_id,draft.content.reply_id)&&m.message===draft.content.message);
    }
    const bid=await this.ownedProposal(client,accountId,id);
    return sameId(projectId(bid),draft.content.project_id)&&bid.description===draft.content.description&&hash(this.milestones(bid.milestones??[]))===hash(draft.content.milestones);
  }
  private async statistics(tenant:string,client:Client,id:any) {
    return this.store.withLock(this.ns(tenant,'writes'),async()=>{
      const p=this.policy(tenant,'statistics'),key=String(numericId(id));const cache=this.store.get<any>(this.ns(tenant,'statistics'),key);
      if(cache?.status==='SUBMITTING'){cache.status='UNKNOWN';this.store.put(this.ns(tenant,'statistics'),key,cache);}
      if(cache&&(cache.status==='UNKNOWN'||cache.expiresAt>this.clock()))return {status:cache.status,statistics:cache.value,cached:true};
      const plans=await client.getPlans();if(count(plans?.statistics_remaining)<1)return fail('STATISTICS_QUOTA_EXHAUSTED','No verified included statistics quota is available.');
      // Reserve before the potentially quota-consuming GET. Unknown outcomes consume the local reservation.
      this.store.transaction(()=>{this.reserve(tenant,p,0,0,1);this.store.put(this.ns(tenant,'statistics'),key,{status:'SUBMITTING',expiresAt:this.clock()+5*60*1000});});
      let status:State='UNKNOWN',value:any;
      try{value=await client.competitionStatistics(numericId(id));status='CONFIRMED';}
      catch(e:any){status=e?.status===402?'NEEDS_PAYMENT':e?.status===401?'REAUTH_REQUIRED':e?.status>=400&&e.status<500?'REJECTED':'UNKNOWN';}
      this.store.put(this.ns(tenant,'statistics'),key,{status,value,expiresAt:this.clock()+5*60*1000});return {status,statistics:value,cached:false};
    });
  }
}
