import type { Express, Request, Response } from 'express';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import type { Store } from './store.js';
import { KarlancerClient } from './karlancer.js';
import { policySchema } from './domain.js';
import { professionalProfileShape } from './tool-catalog.js';
import {profileKeys,parseAiFields} from './field-controls.js';
import {page,renderDashboard} from './portal-view.js';

interface PortalUser { id: string; name: string; phoneHash: string; accountId: number; admin: boolean; disabled?:boolean; }
interface PortalSession { userId: string; csrf: string; }
interface Prelogin { csrf: string; inviteHash?: string; phoneHash?: string; requestedAt?: number; returnTo?: string; reconnectUserId?: string; }
interface Invite { createdBy: string; expiresAt: number; usedBy?: string; }
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('hex');
const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]!));
const same = (a: unknown, b: string) => typeof a === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function normalizedPhone(value: unknown): string | undefined {
  if(typeof value !== 'string' || value.length > 40) return;
  let digits = value.replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776)).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632)).replace(/\D/g, '');
  if(digits.startsWith('0098')) digits = digits.slice(4);
  else if(digits.startsWith('98')) digits = digits.slice(2);
  if(digits.startsWith('0')) digits = digits.slice(1);
  return /^9\d{9}$/.test(digits) ? digits : undefined;
}
const defaultPolicy = () => ({ version: 1, proposalsEnabled: false, repliesEnabled: false, minNetIncome: 0, maxDurationDays: 30, dailyMaxProposals: 0, dailyMaxTokens: 0, dailyMaxStatistics: 0, cashPremiumLimit: 0 as const, allowIncludedPromotions: false });
const profileFields = profileKeys;
const arrayFields = new Set(['skills','limitations','experience','portfolioUrls']);
const labels: Record<string,string> = {name:'نام',title:'عنوان حرفه‌ای',summary:'معرفی',language:'زبان',timezone:'منطقه زمانی',skills:'مهارت‌ها، هر مورد در یک خط',limitations:'محدودیت‌ها، هر مورد در یک خط',experience:'سوابق قابل استناد، هر مورد در یک خط',portfolioUrls:'نشانی نمونه‌کارها، هر مورد در یک خط',resumeUrl:'نشانی رزومه',tone:'لحن پاسخ',signature:'امضا',minNetIncome:'حداقل درآمد خالص (تومان)',maxDurationDays:'بیشترین مدت پروژه (روز)',dailyMaxProposals:'سقف روزانه پیشنهاد',dailyMaxTokens:'سقف روزانه اعتبار پیشنهاد',dailyMaxStatistics:'سقف روزانه آمار رقبا'};
const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${csrf}">`;

export function installPortal(app: Express, { store, baseUrl, ownerPhoneHash }: { store: Store; baseUrl: string; ownerPhoneHash: string }): { getPortalAccount(req: Request): string | undefined } {
  const origin = new URL(baseUrl).origin;
  const cookieOptions = { httpOnly: true, secure: true, sameSite: 'lax' as const, path: '/' };
  const cookieValue = (req: Request, name: string) => {
    const raw = req.headers.cookie?.split(';').map(v=>v.trim()).find(v=>v.startsWith(`${name}=`))?.slice(name.length+1);
    return raw && /^[a-f0-9]{64}$/.test(raw) ? raw : undefined;
  };
  const sessionKey = (req: Request) => {const cookie=cookieValue(req,'__Host-kmcp_session');return cookie?hash(cookie):undefined;};
  const preKey = (req: Request) => {const cookie=cookieValue(req,'__Host-kmcp_login');return cookie?hash(cookie):undefined;};
  const session = (req: Request) => {const key=sessionKey(req);return key?store.get<PortalSession>('portal_sessions',key):undefined;};
  const getPortalAccount = (req: Request) => {const current=session(req);const user=current?store.get<PortalUser>('users',current.userId):undefined;return user&&!user.disabled?user.id:undefined;};
  const deny = (res: Response, status=403) => res.status(status).type('html').send(page('درخواست انجام نشد','<p>اطلاعات ورود یا مجوز درخواست معتبر نیست. دوباره از صفحه ورود شروع کنید.</p><a href="/login">ورود</a>'));
  const validWrite = (req: Request, csrf: string) => req.headers.origin===origin && same(req.body?.csrf,csrf);
  const pending = (req: Request) => {const key=preKey(req);const data=key?store.get<Prelogin>('portal_login',key):undefined;return key&&data?{key,data}:undefined;};
  const clearPending = (key: string) => {store.delete('portal_login',key);store.delete('vault',JSON.stringify([key,'portal-login']));};
  const existingUser = (phoneHash: string) => store.list<PortalUser>('users').find(row=>row.value.phoneHash===phoneHash)?.value;
  const validInvite = (inviteHash?: string) => {const invite=inviteHash?store.get<Invite>('invites',inviteHash):undefined;return invite&&!invite.usedBy&&invite.expiresAt>Date.now()?invite:undefined;};
  const allowed = (phoneHash: string, inviteHash?: string) => same(phoneHash,ownerPhoneHash) || !!existingUser(phoneHash) || !!validInvite(inviteHash);
  const throttle = (req: Request, type: string, identity: string, limit: number) => {
    const keys=[hash(`${type}:ip:${req.ip??req.socket.remoteAddress??'unknown'}`),hash(`${type}:phone:${identity}`)];
    const counts=keys.map(key=>store.get<number>('portal_limits',key)??0);
    if(counts.some(value=>value>=limit)) return false;
    keys.forEach((key,index)=>store.put('portal_limits',key,counts[index]+1,15*60));return true;
  };
  const authWrite = (req: Request, res: Response) => {
    const current=session(req);const user=current?store.get<PortalUser>('users',current.userId):undefined;
    if(!current||!user||user.disabled||!validWrite(req,current.csrf)){deny(res);return;}return {current,user};
  };
  app.use((req,res,next)=>{if(['/','/login','/settings','/logout','/invites','/disconnect'].includes(req.path)||req.path.startsWith('/login/')){res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','same-origin');}next();});

  app.get('/login',(req,res)=>{
    const requestedReturn=req.query.return??req.query.returnTo;
    const returnTo=typeof requestedReturn==='string'&&/^\/interaction\/[A-Za-z0-9_-]{1,200}$/.test(requestedReturn)?requestedReturn:undefined;
    const authenticated=getPortalAccount(req);
    let login=pending(req);
    if(authenticated&&req.query.reconnect!=='1'&&!login?.data.reconnectUserId){res.redirect(303,returnTo??'/');return;}
    if(!login){const raw=random();const key=hash(raw);login={key,data:{csrf:random()}};res.cookie('__Host-kmcp_login',raw,{...cookieOptions,maxAge:10*60*1000});}
    if(returnTo)login.data.returnTo=returnTo;
    if(authenticated&&req.query.reconnect==='1')login.data.reconnectUserId=authenticated;
    const invitation=typeof req.query.invite==='string'?req.query.invite:undefined;
    if(invitation&&invitation.length<=200&&validInvite(hash(invitation))) login.data.inviteHash=hash(invitation);
    store.put('portal_login',login.key,login.data,10*60);
    const verify=!!login.data.requestedAt;
    res.type('html').send(page(verify?'کد تأیید':'ورود امن به پنل',`<p>کد پیامک را شخصاً وارد کنید. اتصال فقط برای حساب فریلنسری تأییدشده است.</p><form method="post" action="${verify?'/login/verify':'/login/request'}">${csrfField(login.data.csrf)}${verify?'<label for="code">کد پیامک</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{4,10}" required>':'<label for="phone">شماره موبایل</label><input id="phone" name="phone" type="tel" autocomplete="tel" required><label for="invite">کد دعوت (اختیاری)</label><input id="invite" name="invite" autocomplete="off">'}<button type="submit">${verify?'تأیید و اتصال':'دریافت کد'}</button></form>`));
  });
  app.post('/login/request',async(req,res)=>{
    const login=pending(req);if(!login||!validWrite(req,login.data.csrf)){deny(res);return;}
    const phone=normalizedPhone(req.body?.phone);if(!phone){deny(res,400);return;}
    const phoneHash=hash(phone);
    if(login.data.reconnectUserId&&store.get<PortalUser>('users',login.data.reconnectUserId)?.phoneHash!==phoneHash){deny(res);return;}
    if(typeof req.body.invite==='string'&&req.body.invite.length<=200&&req.body.invite)login.data.inviteHash=hash(req.body.invite);
    if(!allowed(phoneHash,login.data.inviteHash)){deny(res);return;}
    if(!throttle(req,'request',phoneHash,5)){deny(res,429);return;}
    try {
      await new KarlancerClient().requestOtp(`0${phone}`);
      login.data.phoneHash=phoneHash;login.data.requestedAt=Date.now();
      store.put('portal_login',login.key,login.data,10*60);store.seal(login.key,'portal-login',{phone:`0${phone}`});
      res.redirect(303,'/login');
    } catch {deny(res,502);}
  });
  app.post('/login/verify',async(req,res)=>{
    const login=pending(req);if(!login||!validWrite(req,login.data.csrf)||!login.data.phoneHash||!login.data.requestedAt||Date.now()-login.data.requestedAt>10*60*1000){deny(res);return;}
    const code=req.body?.code;if(typeof code!=='string'||!/^\d{4,10}$/.test(code)){deny(res,400);return;}
    if(!throttle(req,'verify',login.data.phoneHash,10)){deny(res,429);return;}
    try {
      const secret=store.unseal<{phone:string}>(login.key,'portal-login');if(!secret){deny(res);return;}
      const result=await new KarlancerClient().verifyOtp(secret.phone,code);
      const identity=result?.user;const actualPhone=normalizedPhone(identity?.phone);
      const accountId=Number(identity?.id);
      if(!Number.isSafeInteger(accountId)||accountId<1||identity?.role!=='freelancer'||!actualPhone||hash(actualPhone)!==login.data.phoneHash||
        typeof result?.access_token!=='string'||!result.access_token||result.access_token.length>16000||!/^[Bb]earer$/.test(result?.token_type??'')||!allowed(login.data.phoneHash,login.data.inviteHash)){
        clearPending(login.key);deny(res);return;
      }
      const old=existingUser(login.data.phoneHash);
      if(login.data.reconnectUserId&&old?.id!==login.data.reconnectUserId){clearPending(login.key);deny(res);return;}
      if(old&&(old.disabled||old.accountId!==accountId)){clearPending(login.key);deny(res);return;}
      if(store.list<PortalUser>('users').some(row=>row.value.accountId===accountId&&row.value.phoneHash!==login.data.phoneHash)){clearPending(login.key);deny(res);return;}
      const owner=same(login.data.phoneHash,ownerPhoneHash);
      const user:PortalUser=old??{id:randomUUID(),name:owner?'مدیر سیستم':'کاربر',phoneHash:login.data.phoneHash,accountId,admin:owner};
      const raw=random(),key=hash(raw),newSession={userId:user.id,csrf:random()};
      store.transaction(()=>{
        store.put('users',user.id,user);store.seal(user.id,'karlancer',{token:`Bearer ${result.access_token}`,accountId,connectedAt:Date.now()});
        if(!store.get('profile',user.id))store.put('profile',user.id,{version:1});
        if(!store.get('policy',user.id))store.put('policy',user.id,defaultPolicy());
        if(!old&&login.data.inviteHash&&!owner){const invite=validInvite(login.data.inviteHash);if(!invite)throw Error('Invite expired');store.put('invites',login.data.inviteHash,{...invite,usedBy:user.id},Math.max(1,Math.ceil((invite.expiresAt-Date.now())/1000)));}
        store.put('portal_sessions',key,newSession,30*24*60*60);clearPending(login.key);
      });
      const previousKey=sessionKey(req);if(previousKey)store.delete('portal_sessions',previousKey);
      res.clearCookie('__Host-kmcp_login',cookieOptions);res.cookie('__Host-kmcp_session',raw,{...cookieOptions,maxAge:30*24*60*60*1000});res.redirect(303,login.data.returnTo??'/');
    }catch{deny(res,502);}
  });

  const dashboard=(req:Request,res:Response,options:{status?:number;error?:string;saved?:boolean}={})=>{
    const current=session(req),tenant=getPortalAccount(req);if(!current||!tenant){res.redirect(303,'/login');return;}
    const user=store.get<PortalUser>('users',tenant)!;const profile=store.get<any>('profile',tenant)??{};const policy=store.get<any>('policy',tenant)??defaultPolicy();
    const connected=!!store.unseal(tenant,'karlancer');
    const action=(path:string,label:string)=>`<form class="actions" method="post" action="${path}">${csrfField(current.csrf)}<button type="submit">${label}</button></form>`;
    const decisions=store.list<any>(`draft:${tenant}`).filter(({value:d})=>d.tenant===tenant&&d.kind==='reply'&&d.needsOwnerDecision&&!d.operationId&&d.expiresAt>Date.now()).map(({key,value:d})=>`<fieldset><legend>تأیید تعهد در پاسخ مشتری</legend><p>این متن پس از تأیید شما و فراخوانی ابزار ارسال توسط ایجنت قابل ارسال است:</p><p style="white-space:pre-wrap">${escape(d.content?.message)}</p>${action(`/drafts/${encodeURIComponent(key)}/approve`,'تأیید همین متن')}</fieldset>`).join('');
    res.status(options.status??200).type('html').send(renderDashboard({baseUrl,user,profile,policy,csrf:current.csrf,connected,decisionsHtml:decisions,...options}));
  };
  app.get('/',(req,res)=>dashboard(req,res,{saved:req.query.saved==='1'}));
  app.post('/settings',async(req,res)=>{
    const auth=authWrite(req,res);if(!auth)return;
    await store.withLock(`writes:${auth.user.id}`,async()=>{
      const previous=store.get<any>('profile',auth.user.id)??{version:0},old=store.get<any>('policy',auth.user.id)??defaultPolicy();
      for(const [input,version] of [['profileVersion',previous.version],['policyVersion',old.version]] as const){
        const supplied=req.body?.[input];if(supplied!==undefined&&(typeof supplied!=='string'||!/^\d+$/.test(supplied)||Number(supplied)!==version)){dashboard(req,res,{status:409,error:'تنظیمات از زمان باز شدن فرم تغییر کرده است. مقادیر تازه را بررسی و دوباره ویرایش کنید.'});return;}
      }
      let aiFields;
      try{const raw=req.body?.aiFields;aiFields=req.body?.controlsSubmitted==='1'?parseAiFields(raw===undefined?[]:typeof raw==='string'?[raw]:raw):parseAiFields(old.aiFields??[]);if(req.body?.controlsSubmitted!=='1'&&raw!==undefined)throw Error('Missing control version');}
      catch{dashboard(req,res,{status:400,error:'گزینه‌های اختیار AI معتبر نیستند. دوباره انتخاب کنید.'});return;}
      const fields:Record<string,unknown>={};for(const field of profileFields)if(previous[field]!==undefined)fields[field]=previous[field];
      for(const field of profileFields){const value=req.body?.[field];if(value===undefined)continue;if(typeof value!=='string'){dashboard(req,res,{status:400,error:'مقدار یکی از فیلدهای پروفایل معتبر نیست.'});return;}const trimmed=value.trim();if(!trimmed)delete fields[field];else fields[field]=arrayFields.has(field)?trimmed.split(/\r?\n/).map(v=>v.trim()).filter(Boolean):trimmed;}
      const profile=z.object(professionalProfileShape).strict().safeParse(fields);
      const numeric=(name:string)=>req.body?.[name]===undefined?old[name]:typeof req.body[name]==='string'&&/^\d+$/.test(req.body[name])?Number(req.body[name]):NaN;
      const enabled=(name:string)=>req.body?.[name]===undefined&&aiFields.includes(name as any)?old[name]:req.body?.[name]==='on';
      const policy=policySchema.safeParse({version:old.version+1,aiFields,proposalsEnabled:enabled('proposalsEnabled'),repliesEnabled:enabled('repliesEnabled'),allowIncludedPromotions:enabled('allowIncludedPromotions'),cashPremiumLimit:0,minNetIncome:numeric('minNetIncome'),maxDurationDays:numeric('maxDurationDays'),dailyMaxProposals:numeric('dailyMaxProposals'),dailyMaxTokens:numeric('dailyMaxTokens'),dailyMaxStatistics:numeric('dailyMaxStatistics')});
      if(!profile.success||!policy.success){dashboard(req,res,{status:400,error:'نشانی‌ها و مقدارهای عددی را بررسی کنید. قیمت به تومان و مدت بین ۱ تا ۳۶۵ روز است.'});return;}
      store.transaction(()=>{store.put('profile',auth.user.id,{...profile.data,version:previous.version+1});store.put('policy',auth.user.id,policy.data);});
      res.redirect(303,'/?saved=1');
    });
  });
  app.post('/drafts/:id/approve',async(req,res)=>{
    res.set('Cache-Control','no-store');const auth=authWrite(req,res);if(!auth)return;
    await store.withLock(`writes:${auth.user.id}`,async()=>{
      const id=String(req.params.id),draft=store.get<any>(`draft:${auth.user.id}`,id);
      if(!draft||draft.tenant!==auth.user.id){deny(res,404);return;}
      if(draft.kind!=='reply'||!draft.needsOwnerDecision||draft.operationId||draft.expiresAt<=Date.now()){deny(res,409);return;}
      store.put(`draft:${auth.user.id}`,id,{...draft,needsOwnerDecision:false,ownerApprovedAt:Date.now()});res.redirect(303,'/');
    });
  });
  app.post('/logout',(req,res)=>{const auth=authWrite(req,res);if(!auth)return;const key=sessionKey(req);if(key)store.delete('portal_sessions',key);res.clearCookie('__Host-kmcp_session',cookieOptions);res.redirect(303,'/login');});
  app.post('/disconnect',async(req,res)=>{const auth=authWrite(req,res);if(!auth)return;await store.withLock(`writes:${auth.user.id}`,async()=>store.delete('vault',JSON.stringify([auth.user.id,'karlancer'])));res.redirect(303,'/');});
  app.post('/invites',(req,res)=>{const auth=authWrite(req,res);if(!auth)return;if(!auth.user.admin){deny(res);return;}const token=random();store.put('invites',hash(token),{createdBy:auth.user.id,expiresAt:Date.now()+7*24*60*60*1000},7*24*60*60);const url=`${baseUrl.replace(/\/$/,'')}/login?invite=${token}`;res.type('html').send(page('دعوت کاربر',`<p>این پیوند یک بار و تا هفت روز معتبر است:</p><a href="${escape(url)}">${escape(url)}</a><p><a href="/">بازگشت</a></p>`));});
  return {getPortalAccount};
}
