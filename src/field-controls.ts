export const profileKeys = ['name','title','summary','language','timezone','skills','limitations','experience','portfolioUrls','resumeUrl','tone','signature'] as const;
export const policyKeys = ['minNetIncome','maxDurationDays','dailyMaxProposals','dailyMaxTokens','dailyMaxStatistics','proposalsEnabled','repliesEnabled','allowIncludedPromotions'] as const;
export const delegatableKeys = [...profileKeys,...policyKeys] as const;
export type DelegatableKey = typeof delegatableKeys[number];

const allowedKeys = new Set<string>(delegatableKeys);

/** Never coerce form values or silently discard an unknown authority key. */
export function parseAiFields(value:unknown):DelegatableKey[] {
  if(!Array.isArray(value)||value.length>delegatableKeys.length) throw new TypeError('AI fields must be an array of unique supported field names.');
  const result:DelegatableKey[]=[];
  for(const field of value) {
    if(typeof field!=='string'||!allowedKeys.has(field)||result.includes(field as DelegatableKey)) throw new TypeError('AI fields must be an array of unique supported field names.');
    result.push(field as DelegatableKey);
  }
  return result;
}

export function fieldControls(aiFields:readonly string[]):{field:string,mode:'manual'|'ai'}[] {
  const delegated=new Set(parseAiFields(aiFields));
  return delegatableKeys.map(field=>({field,mode:delegated.has(field)?'ai':'manual'}));
}

export function isAiField(policy:unknown,field:DelegatableKey):boolean {
  if(!policy||typeof policy!=='object'||Array.isArray(policy)||!Object.hasOwn(policy,'aiFields')) return false;
  try {return parseAiFields((policy as {aiFields:unknown}).aiFields).includes(field);}
  catch {return false;}
}
