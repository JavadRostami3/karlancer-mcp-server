(()=>{'use strict';
 const form=document.getElementById('settings-form');let dirty=false;let submitting=false;
 const markDirty=()=>{dirty=true;document.querySelector('.savebar')?.classList.add('dirty');const text=document.getElementById('save-status-text');if(text)text.textContent='تغییرات ذخیره‌نشده دارید';};
 const syncField=field=>{const ai=field.querySelector('input[name="aiFields"]')?.checked===true;field.classList.toggle('is-ai',ai);field.querySelectorAll('[data-ai-value]').forEach(input=>input.remove());field.querySelectorAll('.manual-control').forEach(input=>{input.disabled=ai;if(ai){const retained=document.createElement('input');retained.type='hidden';retained.name=input.name;retained.value=input.type==='checkbox'?(input.checked?'on':''):input.value;retained.dataset.aiValue='';field.append(retained);}});};
 document.querySelectorAll('[data-field]').forEach(field=>{syncField(field);field.querySelector('input[name="aiFields"]')?.addEventListener('change',()=>syncField(field));});
 form?.addEventListener('input',markDirty);form?.addEventListener('change',markDirty);
 form?.addEventListener('submit',()=>{submitting=true;const button=form.querySelector('button[type=submit]');if(button){button.disabled=true;const text=button.querySelector('span');if(text)text.textContent='در حال ذخیره…';}});
 window.addEventListener('beforeunload',event=>{if(dirty&&!submitting){event.preventDefault();event.returnValue='';}});
 let toastTimer;const toast=message=>{const target=document.getElementById('toast');if(!target)return;target.textContent=message;target.classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>target.classList.remove('visible'),2800);};
 document.querySelectorAll('[data-copy]').forEach(button=>button.addEventListener('click',async()=>{const text=document.getElementById(button.dataset.copy)?.textContent?.trim();if(!text)return;try{await navigator.clipboard.writeText(text);toast('نشانی اتصال کپی شد');}catch{toast('کپی انجام نشد؛ نشانی را انتخاب و کپی کنید.');}}));
 const sections=[...document.querySelectorAll('.settings-section[id]')];const navLinks=[...document.querySelectorAll('[data-nav]')];
 const activate=id=>navLinks.forEach(a=>{const active=a.dataset.nav===id;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','location');else a.removeAttribute('aria-current');});
 navLinks.forEach(a=>a.addEventListener('click',()=>activate(a.dataset.nav)));
 if('IntersectionObserver'in window){const observer=new IntersectionObserver(entries=>{const visible=entries.filter(e=>e.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio);if(visible[0])activate(visible[0].target.id);},{rootMargin:'-10% 0px -55% 0px',threshold:[0,.1,.5]});sections.forEach(section=>observer.observe(section));}
 activate(location.hash.slice(1)||'profile');
})();
