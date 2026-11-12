// Elevate Systems Consulting — PGCC Certification Tracker Cloudflare Worker
// Free prototype: Cloudflare D1 only. Evidence is DEMO METADATA, never a stored document.
const enc = new TextEncoder();
const SESSION_HOURS = 8;
const ITERATIONS = 100000;
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...extra}});
const fail = (message, status = 400) => json({error:message},status);
const uuid = () => crypto.randomUUID();
const hex = bytes => Array.from(new Uint8Array(bytes)).map(x=>x.toString(16).padStart(2,'0')).join('');
const unhex = str => new Uint8Array(str.match(/../g).map(x=>parseInt(x,16)));
const sha = async str => hex(await crypto.subtle.digest('SHA-256',enc.encode(str)));
const clean = (value,max=200) => String(value ?? '').trim().slice(0,max);
const isDate = v => typeof v==='string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`)) && new Date(`${v}T00:00:00Z`).toISOString().slice(0,10)===v;
const safeUrl = value => !value || (()=>{try {return new URL(value).protocol==='https:'}catch{return false}})();
const isoPlusHours = hours => new Date(Date.now()+hours*3600000).toISOString();
const now = () => new Date().toISOString();
const parseJSON = async req => {if ((Number(req.headers.get('content-length'))||0)>16000) throw new Error('Request too large'); const s=await req.text(); if(s.length>16000) throw new Error('Request too large'); try{return JSON.parse(s)}catch{throw new Error('Invalid JSON')}};
async function derive(password,salt,iterations=ITERATIONS){
 const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:unhex(salt),iterations,hash:'SHA-256'},key,256));
}
async function hashPassword(password){const salt=hex(crypto.getRandomValues(new Uint8Array(16))); return {salt,hash:await derive(password,salt),iterations:ITERATIONS};}
function strong(password){return typeof password==='string' && password.length>=12 && password.length<=128 && /[A-Za-z]/.test(password) && /\d/.test(password);}
async function notify(env,userId,title,message,certId=null){
 await env.DB.prepare('INSERT INTO notifications (id,user_id,title,message,certification_id) VALUES (?,?,?,?,?)')
  .bind(uuid(),userId,clean(title,160),clean(message,800),certId).run();
}
async function audit(env,actor,event,target,metadata={}){await env.DB.prepare('INSERT INTO audit_log (id,actor_id,event,target_id,metadata) VALUES (?,?,?,?,?)').bind(uuid(),actor||null,event,target||null,JSON.stringify(metadata)).run();}
async function getUser(req,env){
 const a=req.headers.get('authorization')||''; if(!a.startsWith('Bearer ')) return null;
 const token=a.slice(7); if(!/^[a-f0-9]{64}$/.test(token)) return null;
 const hashed=await sha(token);
 return env.DB.prepare(`SELECT u.id,u.email,u.full_name,u.role,u.must_change_password,u.active,s.token_hash
 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(hashed,now()).first();
}
const publicUser = u => ({id:u.id,email:u.email,full_name:u.full_name,role:u.role,must_change_password:!!u.must_change_password});
const reviewer = u => ['admin','reviewer'].includes(u.role);
const admin = u => u.role==='admin';
async function loginRate(env,key){const row=await env.DB.prepare('SELECT count,window_start FROM login_attempts WHERE key=?').bind(key).first(); if(row && Date.now()-Date.parse(row.window_start)<15*60*1000 && row.count>=8) return false; return true;}
async function markAttempt(env,key,success){if(success){await env.DB.prepare('DELETE FROM login_attempts WHERE key=?').bind(key).run();return;} const stamp=now(); await env.DB.prepare(`INSERT INTO login_attempts (key,count,window_start) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN julianday(?) - julianday(window_start)>15.0/1440 THEN 1 ELSE count+1 END,window_start=CASE WHEN julianday(?) - julianday(window_start)>15.0/1440 THEN ? ELSE window_start END`).bind(key,stamp,stamp,stamp,stamp,stamp).run();}
async function withAuth(req,env,handler,roles=null){const u=await getUser(req,env); if(!u) return fail('Please sign in',401);if(roles&&!roles.includes(u.role)) return fail('Not authorized',403);if(u.must_change_password) return fail('Change your temporary password first',403);return handler(u);}
function validateCert(b){
 const title=clean(b.title,120),issuer=clean(b.issuer,120),credential_id=clean(b.credential_id,120),verification_url=clean(b.verification_url,500),earned_on=clean(b.earned_on,10),expires_on=clean(b.expires_on,10);
 if(title.length<2||issuer.length<2) throw new Error('Certification and issuer are required');
 if(!isDate(earned_on)||earned_on>new Date().toISOString().slice(0,10)) throw new Error('Invalid earned date');
 if(expires_on&&(!isDate(expires_on)||expires_on<earned_on)) throw new Error('Invalid expiry date');
 if(!safeUrl(verification_url)) throw new Error('Verification URL must use HTTPS');
 return {title,issuer,credential_id,verification_url,earned_on,expires_on:expires_on||null};
}
// V5: deterministic rule engine for demo-only workflows; no external service calls.
async function applyWorkflow(env, certId, eventName, actorId) {
 const cert=await env.DB.prepare('SELECT id,title,student_id,status,updated_at FROM certifications WHERE id=?').bind(certId).first();
 if(!cert) return;
 const rules=(await env.DB.prepare('SELECT id,action,priority,days_due FROM workflow_rules WHERE event=? AND enabled=1 ORDER BY created_at LIMIT 20').bind(eventName).all()).results;
 for(const rule of rules){
  const key=rule.id+':'+eventName+':'+certId+':'+cert.updated_at;
  // UNIQUE event key avoids duplicate tasks from repeated deliveries.
  if(rule.action==='task'){
   const assigned=await env.DB.prepare("SELECT id FROM users WHERE role='reviewer' AND active=1 ORDER BY created_at ASC LIMIT 1").first();
   const assignedId=assigned?.id||null;
   const due=new Date(Date.now()+Math.max(1,Math.min(Number(rule.days_due)||3,30))*86400000).toISOString();
   await env.DB.prepare(`INSERT OR IGNORE INTO workflow_tasks(id,event_key,certification_id,title,priority,status,assigned_to,due_at,created_by)
    VALUES(?,?,?, ?,?,'open',?,?,?)`).bind(uuid(),key,certId,'Review '+cert.title,rule.priority,assignedId,due,actorId).run();
   if(assignedId) await notify(env,assignedId,'Review task assigned','A certification requires review.',certId);
  }else if(rule.action==='notify'){
   await notify(env,cert.student_id,'Certification update',cert.title+' — '+eventName.replaceAll('_',' '),certId);
  }
 }
}
async function route(req,env,path){
 const method=req.method,segments=path.split('/').filter(Boolean), [root,id,action]=segments;
 if(method==='GET' && path==='/api/health') return json({status:'ok',service:'PGCC Certification Tracker API'});
 if(method==='POST' && path==='/api/setup'){
  if(!env.BOOTSTRAP_TOKEN || req.headers.get('x-bootstrap-token')!==env.BOOTSTRAP_TOKEN) return fail('Not found',404);
  const exists=await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();if(exists)return fail('An administrator already exists; setup is disabled',409);
  const b=await parseJSON(req),email=clean(b.email,200).toLowerCase(),name=clean(b.full_name,100);
  if(!/^\S+@\S+\.\S+$/.test(email)||name.length<2||!strong(b.password))return fail('Valid name/email and 12+ character password with letters and numbers required');
  const pw=await hashPassword(b.password),uid=uuid();
  await env.DB.prepare('INSERT INTO users (id,email,full_name,role,password_hash,password_salt,password_iterations,must_change_password) VALUES (?,?,?,?,?,?,?,0)').bind(uid,email,name,'admin',pw.hash,pw.salt,pw.iterations).run();
  await audit(env,uid,'bootstrap_admin',uid);return json({message:'Administrator created. Remove BOOTSTRAP_TOKEN secret now.'},201);
 }
 if(method==='POST' && path==='/api/auth/login'){
  const b=await parseJSON(req),email=clean(b.email,200).toLowerCase(),password=String(b.password||'');
  const ip=req.headers.get('cf-connecting-ip')||'local'; const key=await sha(ip+':'+email);
  if(!await loginRate(env,key))return fail('Too many attempts. Try again in 15 minutes.',429);
  const u=await env.DB.prepare('SELECT * FROM users WHERE email=? AND active=1').bind(email).first();
  const correct=u && (await derive(password,u.password_salt,u.password_iterations))===u.password_hash;
  await markAttempt(env,key,!!correct);
  if(!correct) return fail('Invalid email or password',401);
  const token=hex(crypto.getRandomValues(new Uint8Array(32))),hash=await sha(token),expiry=isoPlusHours(SESSION_HOURS);
  await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(hash,u.id,expiry).run();
  await audit(env,u.id,'login',u.id);
  return json({token,expires_at:expiry,user:publicUser(u)});
 }
 if(method==='GET' && path==='/api/auth/me'){const u=await getUser(req,env);return u?json({user:publicUser(u)}):fail('Please sign in',401);}
 if(method==='POST' && path==='/api/auth/logout'){const u=await getUser(req,env);if(u) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(u.token_hash).run();return json({ok:true});}
 if(method==='POST' && path==='/api/auth/password'){
  const u=await getUser(req,env);if(!u)return fail('Please sign in',401);
  const b=await parseJSON(req),stored=await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(u.id).first();
  if(await derive(String(b.current_password||''),stored.password_salt,stored.password_iterations)!==stored.password_hash) return fail('Current password is wrong',403);
  if(!strong(b.new_password))return fail('New password requires 12+ characters, including letters and numbers');
  const p=await hashPassword(b.new_password);
  await env.DB.prepare('UPDATE users SET password_hash=?,password_salt=?,password_iterations=?,must_change_password=0 WHERE id=?').bind(p.hash,p.salt,p.iterations,u.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').bind(u.id,u.token_hash).run();
  await audit(env,u.id,'password_changed',u.id);return json({ok:true});
 }
 if(root==='api' && id==='users' && method==='GET' && !action) return withAuth(req,env,async u=>json({items:(await env.DB.prepare('SELECT id,email,full_name,role,active,created_at FROM users ORDER BY full_name LIMIT 500').all()).results}),['admin']);
 if(path==='/api/users'&&method==='POST')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),email=clean(b.email,200).toLowerCase(),name=clean(b.full_name,100),role=clean(b.role,20);
  if(!/^\S+@\S+\.\S+$/.test(email)||name.length<2||!['admin','reviewer','student'].includes(role)||!strong(b.password))return fail('Valid name, email, role and strong temporary password required');
  const existing=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();if(existing)return fail('Email already exists',409);
  const p=await hashPassword(b.password),uid=uuid();
  await env.DB.prepare('INSERT INTO users (id,email,full_name,role,password_hash,password_salt,password_iterations) VALUES (?,?,?,?,?,?,?)').bind(uid,email,name,role,p.hash,p.salt,p.iterations).run();
  await audit(env,u.id,'user_created',uid,{role});await notify(env,uid,'Account created','Your '+role+' account has been created.',null);return json({id:uid},201);
 },['admin']);
 if(root==='api'&&id==='users'&&segments.length===4&&action&&segments[3]==='active'&&method==='PATCH')return withAuth(req,env,async u=>{
  if(action===u.id)return fail('Cannot deactivate yourself');
  const b=await parseJSON(req);if(typeof b.active!=='boolean')return fail('active must be a boolean');
  const result=await env.DB.prepare('UPDATE users SET active=? WHERE id=?').bind(b.active?1:0,action).run();if(!result.meta.changes)return fail('User not found',404);
  if(!b.active)await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(action).run();
  await audit(env,u.id,'user_status_changed',action,{active:b.active});return json({ok:true});
 },['admin']);
 if(path==='/api/certifications' && method==='GET')return withAuth(req,env,async u=>{
  const query=reviewer(u)?'':'WHERE c.student_id=?';
  const sql=`SELECT c.*,s.full_name AS student_name,s.email AS student_email,r.full_name AS reviewer_name FROM certifications c JOIN users s ON s.id=c.student_id LEFT JOIN users r ON r.id=c.reviewed_by ${query} ORDER BY c.created_at DESC LIMIT 500`;
  return json({items:(await (reviewer(u)?env.DB.prepare(sql):env.DB.prepare(sql).bind(u.id)).all()).results});
 });
 if(path==='/api/certifications'&&method==='POST')return withAuth(req,env,async u=>{
  if(u.role!=='student')return fail('Only students can submit credentials',403);
  const b=validateCert(await parseJSON(req)),id=uuid();
  await env.DB.prepare(`INSERT INTO certifications (id,student_id,title,issuer,credential_id,verification_url,earned_on,expires_on) VALUES (?,?,?,?,?,?,?,?)`).bind(id,u.id,b.title,b.issuer,b.credential_id,b.verification_url,b.earned_on,b.expires_on).run();
  await audit(env,u.id,'certification_created',id);await applyWorkflow(env,id,'submitted',u.id);return json({id},201);
 });
 if(root==='api' && id==='certifications' && action){
  const certId=action,verb=segments[3];
  if(method==='GET'&&segments.length===3)return withAuth(req,env,async u=>{
   const c=await env.DB.prepare('SELECT * FROM certifications WHERE id=?').bind(certId).first();if(!c)return fail('Not found',404);
   if(!reviewer(u)&&c.student_id!==u.id)return fail('Not authorized',403);return json({item:c});
  });
  if(method==='PUT'&&segments.length===3)return withAuth(req,env,async u=>{
   const c=await env.DB.prepare('SELECT * FROM certifications WHERE id=?').bind(certId).first();if(!c)return fail('Not found',404);
   if(c.student_id!==u.id||!['pending','needs_revision'].includes(c.status))return fail('This submission cannot be edited',403);
   const b=validateCert(await parseJSON(req));
   await env.DB.prepare(`UPDATE certifications SET title=?,issuer=?,credential_id=?,verification_url=?,earned_on=?,expires_on=?,status='pending',notes='',reviewed_by=NULL,reviewed_at=NULL,updated_at=? WHERE id=?`).bind(b.title,b.issuer,b.credential_id,b.verification_url,b.earned_on,b.expires_on,now(),certId).run();
   await audit(env,u.id,'certification_updated',certId);await applyWorkflow(env,certId,'submitted',u.id);return json({ok:true});
  });
  if(method==='POST'&&verb==='demo-evidence')return withAuth(req,env,async u=>{
   const c=await env.DB.prepare('SELECT * FROM certifications WHERE id=?').bind(certId).first();if(!c)return fail('Not found',404);
   if(c.student_id!==u.id||!['pending','needs_revision'].includes(c.status))return fail('Not permitted',403);
   const b=await parseJSON(req);const evidence=clean(b.description,150);
   if(evidence.length<5)return fail('Describe the fictional evidence in at least 5 characters');
   await env.DB.prepare(`UPDATE certifications SET proof_key='demo-only',proof_name=?,proof_type='demo',status='pending',updated_at=? WHERE id=?`).bind(evidence,now(),certId).run();
   await audit(env,u.id,'demo_evidence_recorded',certId,{demo_only:true});return json({ok:true,demo_only:true});
  });
  if(method==='GET'&&verb==='proof')return fail('This free prototype does not store or serve uploaded files',404);
  if(method==='POST'&&verb==='review')return withAuth(req,env,async u=>{
   const b=await parseJSON(req),status=clean(b.status,20),notes=clean(b.notes,1000);
   if(!['approved','rejected','needs_revision'].includes(status))return fail('Invalid review status');
   if(status!=='approved' && notes.length<3)return fail('Explain the rejection or requested revision');
   const c=await env.DB.prepare('SELECT * FROM certifications WHERE id=?').bind(certId).first();if(!c)return fail('Not found',404);
   if(c.status!=='pending')return fail('Only pending submissions can be reviewed',409);
   if(!c.proof_key && status==='approved')return fail('Record demo evidence before approval');
   if(status==='approved'){const check=await env.DB.prepare('SELECT * FROM verification_checks WHERE certification_id=?').bind(certId).first();if(!check||!check.issuer_checked||!check.identifier_checked||!check.dates_checked||!check.evidence_reviewed)return fail('Complete all four manual review checklist items before approval',409);}
   await env.DB.prepare('UPDATE certifications SET status=?,notes=?,reviewed_by=?,reviewed_at=?,updated_at=? WHERE id=? AND status=?').bind(status,notes,u.id,now(),now(),certId,'pending').run();
   await env.DB.prepare("UPDATE workflow_tasks SET status='completed',completed_at=? WHERE certification_id=? AND status='open'").bind(now(),certId).run();
   await audit(env,u.id,'certification_reviewed',certId,{status});if(status==='needs_revision')await applyWorkflow(env,certId,'needs_revision',u.id);await notify(env,c.student_id,'Certification '+status.replace('_',' '),c.title+(notes?' — '+notes:''),certId);return json({ok:true});
  },['reviewer','admin']);
 }
 if(method==='GET'&&path==='/api/reports/summary')return withAuth(req,env,async u=>{
  const counts=(await env.DB.prepare('SELECT status,COUNT(*) AS total FROM certifications GROUP BY status').all()).results;
  const issuers=(await env.DB.prepare('SELECT issuer,COUNT(*) AS total FROM certifications GROUP BY issuer ORDER BY total DESC LIMIT 10').all()).results;
  const totals=(await env.DB.prepare('SELECT COUNT(*) AS students FROM users WHERE role=\'student\' AND active=1').first());
  return json({counts,issuers,students:totals.students});
 },['reviewer','admin']);
 // v2: personal notification center (no email or paid push provider required)
 if(method==='GET' && path==='/api/notifications')return withAuth(req,env,async u=>{
  const items=(await env.DB.prepare('SELECT id,title,message,certification_id,is_read,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(u.id).all()).results;
  return json({items,unread:items.filter(x=>!x.is_read).length});
 });
 if(method==='PATCH' && /^\/api\/notifications\/[0-9a-f-]+\/read$/.test(path))return withAuth(req,env,async u=>{
  const id=path.split('/')[3];const change=await env.DB.prepare('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?').bind(id,u.id).run();
  return change.meta.changes?json({ok:true}):fail('Notification not found',404);
 });
 // v2: advanced reviewer analytics with single DB query per metric
 if(method==='GET' && path==='/api/reports/advanced')return withAuth(req,env,async u=>{
  const [timeline,expiring,reviewers,activity]=await Promise.all([
   env.DB.prepare("SELECT substr(created_at,1,7) month, COUNT(*) submitted, SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved FROM certifications GROUP BY substr(created_at,1,7) ORDER BY month DESC LIMIT 12").all(),
   env.DB.prepare("SELECT c.id,c.title,c.issuer,c.expires_on,u.full_name student_name FROM certifications c JOIN users u ON u.id=c.student_id WHERE c.status='approved' AND c.expires_on IS NOT NULL AND c.expires_on <= date('now','+60 days') ORDER BY c.expires_on LIMIT 50").all(),
   env.DB.prepare("SELECT u.full_name reviewer,COUNT(*) reviewed FROM certifications c JOIN users u ON u.id=c.reviewed_by WHERE c.reviewed_by IS NOT NULL GROUP BY c.reviewed_by ORDER BY reviewed DESC LIMIT 20").all(),
   env.DB.prepare("SELECT ROUND(AVG((julianday(reviewed_at)-julianday(created_at))*24),1) avg_review_hours FROM certifications WHERE reviewed_at IS NOT NULL").first()
  ]);
  return json({timeline:timeline.results.reverse(),expiring:expiring.results,reviewers:reviewers.results,avg_review_hours:activity.avg_review_hours});
 },['reviewer','admin']);
 // v2: limited-action review queue, indexed in D1 for speed
 if(method==='GET' && path==='/api/review-queue')return withAuth(req,env,async u=>{
  const items=(await env.DB.prepare("SELECT c.id,c.title,c.issuer,c.created_at,c.earned_on,c.proof_name,u.full_name student_name FROM certifications c JOIN users u ON u.id=c.student_id WHERE c.status='pending' ORDER BY c.created_at ASC LIMIT 100").all()).results;
  return json({items});
 },['reviewer','admin']);
 // v3: discoverable certification catalog, curated and maintained by administrators
 if(path==='/api/catalog' && method==='GET')return withAuth(req,env,async u=>json({items:(await env.DB.prepare('SELECT id,title,issuer,category,level,description,verification_url,active FROM catalog WHERE active=1 ORDER BY category,title LIMIT 200').all()).results}));
 if(path==='/api/catalog' && method==='POST')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),title=clean(b.title,120),issuer=clean(b.issuer,120),category=clean(b.category,60)||'General',level=clean(b.level,30)||'Foundational',description=clean(b.description,600),verification_url=clean(b.verification_url,500);
  if(title.length<2||issuer.length<2||!safeUrl(verification_url)||!['Foundational','Intermediate','Advanced','Expert'].includes(level))return fail('Valid certification title, issuer, level and HTTPS verification URL required');
  const entry=uuid();await env.DB.prepare('INSERT INTO catalog (id,title,issuer,category,level,description,verification_url) VALUES (?,?,?,?,?,?,?)').bind(entry,title,issuer,category,level,description,verification_url).run();await audit(env,u.id,'catalog_created',entry);return json({id:entry},201);
 },['admin']);
 if(/^\/api\/catalog\/[^/]+$/.test(path)&&method==='DELETE')return withAuth(req,env,async u=>{
  const id=segments[2],result=await env.DB.prepare('UPDATE catalog SET active=0 WHERE id=?').bind(id).run();if(!result.meta.changes)return fail('Catalog item not found',404);await audit(env,u.id,'catalog_archived',id);return json({ok:true});
 },['admin']);
 // v3: individual development plans, never visible to other students
 if(path==='/api/goals'&&method==='GET')return withAuth(req,env,async u=>{
  if(u.role!=='student')return json({items:[]});
  return json({items:(await env.DB.prepare("SELECT g.*,c.issuer FROM student_goals g LEFT JOIN catalog c ON c.id=g.catalog_id WHERE g.student_id=? ORDER BY CASE g.status WHEN 'in_progress' THEN 0 WHEN 'planned' THEN 1 ELSE 2 END, g.target_date IS NULL,g.target_date LIMIT 200").bind(u.id).all()).results});
 });
 if(path==='/api/goals'&&method==='POST')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),title=clean(b.title,120),notes=clean(b.notes,500),target=clean(b.target_date,10),catalog=clean(b.catalog_id,80)||null;
  if(title.length<2||(target&&!isDate(target)))return fail('Valid goal title and date required');
  if(catalog){const exists=await env.DB.prepare('SELECT id FROM catalog WHERE id=? AND active=1').bind(catalog).first();if(!exists)return fail('Catalog item not found',404)}
  const id=uuid();await env.DB.prepare('INSERT INTO student_goals (id,student_id,catalog_id,title,target_date,notes) VALUES (?,?,?,?,?,?)').bind(id,u.id,catalog,title,target||null,notes).run();await audit(env,u.id,'goal_created',id);return json({id},201);
 },['student']);
 if(/^\/api\/goals\/[^/]+$/.test(path)&&method==='PATCH')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),status=clean(b.status,20);if(!['planned','in_progress','completed'].includes(status))return fail('Invalid goal status');
  const id=segments[2],result=await env.DB.prepare('UPDATE student_goals SET status=? WHERE id=? AND student_id=?').bind(status,id,u.id).run();if(!result.meta.changes)return fail('Goal not found',404);
  await audit(env,u.id,'goal_updated',id,{status});return json({ok:true});
 },['student']);
 if(/^\/api\/goals\/[^/]+$/.test(path)&&method==='DELETE')return withAuth(req,env,async u=>{
  const id=segments[2],result=await env.DB.prepare('DELETE FROM student_goals WHERE id=? AND student_id=?').bind(id,u.id).run();if(!result.meta.changes)return fail('Goal not found',404);
  await audit(env,u.id,'goal_deleted',id);return json({ok:true});
 },['student']);
 // v3: campus news, scoped by role, with administrator authoring
 if(path==='/api/announcements'&&method==='GET')return withAuth(req,env,async u=>json({items:(await env.DB.prepare("SELECT id,title,body,audience,created_at FROM announcements WHERE active=1 AND (audience='all' OR audience=? OR ?='admin') ORDER BY created_at DESC LIMIT 40").bind(u.role,u.role).all()).results}));
 if(path==='/api/announcements'&&method==='POST')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),title=clean(b.title,140),body=clean(b.body,1500),audience=clean(b.audience,20)||'all';
  if(title.length<3||body.length<5||!['all','student','reviewer','admin'].includes(audience))return fail('Title, message and valid audience required');
  const id=uuid();await env.DB.prepare('INSERT INTO announcements (id,title,body,audience,author_id) VALUES (?,?,?,?,?)').bind(id,title,body,audience,u.id).run();await audit(env,u.id,'announcement_created',id,{audience});return json({id},201);
 },['admin']);
 if(/^\/api\/announcements\/[^/]+$/.test(path)&&method==='DELETE')return withAuth(req,env,async u=>{
  const id=segments[2],result=await env.DB.prepare('UPDATE announcements SET active=0 WHERE id=?').bind(id).run();if(!result.meta.changes)return fail('Announcement not found',404);
  await audit(env,u.id,'announcement_archived',id);return json({ok:true});
 },['admin']);
 // v3: per-certification activity timeline, protected with ownership check
 if(/^\/api\/certifications\/[^/]+\/history$/.test(path)&&method==='GET')return withAuth(req,env,async u=>{
  const certId=segments[2],c=await env.DB.prepare('SELECT student_id FROM certifications WHERE id=?').bind(certId).first();if(!c)return fail('Certification not found',404);
  if(!reviewer(u)&&c.student_id!==u.id)return fail('Not authorized',403);
  const events=(await env.DB.prepare("SELECT a.event,a.occurred_at,u.full_name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id WHERE a.target_id=? AND a.event LIKE 'certification_%' ORDER BY a.occurred_at DESC LIMIT 50").bind(certId).all()).results;
  return json({items:events});
 });
 // V4: program pathways. Catalog IDs are matched exactly against approved titles and issuers
 // for a demonstrative coverage estimate; administrators must confirm equivalencies.
 if(method==='GET' && path==='/api/programs') return withAuth(req,env,async u=>{
  const programs=(await env.DB.prepare('SELECT id,title,department,description FROM programs WHERE active=1 ORDER BY title LIMIT 80').all()).results;
  const requirements=(await env.DB.prepare(`SELECT pr.id,pr.program_id,pr.catalog_id,pr.required,c.title,c.issuer,c.category,c.level
   FROM program_requirements pr JOIN catalog c ON c.id=pr.catalog_id WHERE c.active=1 ORDER BY c.title LIMIT 500`).all()).results;
  const enrolled=u.role==='student'?(await env.DB.prepare('SELECT program_id FROM student_programs WHERE student_id=?').bind(u.id).all()).results.map(x=>x.program_id):[];
  let coverage=[];
  if(u.role==='student')coverage=(await env.DB.prepare(`SELECT pr.program_id,pr.catalog_id,COUNT(cert.id) AS approved_count
   FROM program_requirements pr JOIN catalog c ON c.id=pr.catalog_id
   LEFT JOIN certifications cert ON cert.student_id=? AND cert.status='approved'
    AND lower(trim(cert.title))=lower(trim(c.title)) AND lower(trim(cert.issuer))=lower(trim(c.issuer))
   GROUP BY pr.program_id,pr.catalog_id`).bind(u.id).all()).results;
  return json({programs,requirements,enrolled,coverage,disclaimer:'Coverage is an automated title/issuer match for demonstration, not official degree or certification equivalency.'});
 });
 if(method==='POST' && path==='/api/programs') return withAuth(req,env,async u=>{
  const b=await parseJSON(req),title=clean(b.title,140),department=clean(b.department,90)||'Technology',description=clean(b.description,700);
  if(title.length<3)return fail('A program title of at least 3 characters is required');
  const id=uuid();await env.DB.prepare('INSERT INTO programs(id,title,department,description) VALUES (?,?,?,?)').bind(id,title,department,description).run();
  await audit(env,u.id,'program_created',id);return json({id},201);
 },['admin']);
 if(method==='POST' && /^\/api\/programs\/[^/]+\/requirements$/.test(path))return withAuth(req,env,async u=>{
  const programId=segments[2],b=await parseJSON(req),catalogId=clean(b.catalog_id,90);
  const program=await env.DB.prepare('SELECT id FROM programs WHERE id=? AND active=1').bind(programId).first();
  const catalog=await env.DB.prepare('SELECT id FROM catalog WHERE id=? AND active=1').bind(catalogId).first();
  if(!program||!catalog)return fail('Program or catalog entry not found',404);
  const prior=await env.DB.prepare('SELECT id FROM program_requirements WHERE program_id=? AND catalog_id=?').bind(programId,catalogId).first();
  if(prior)return fail('Credential already mapped to this program',409);
  const id=uuid();await env.DB.prepare('INSERT INTO program_requirements(id,program_id,catalog_id) VALUES (?,?,?)').bind(id,programId,catalogId).run();
  await audit(env,u.id,'program_requirement_added',programId,{catalog_id:catalogId});return json({id},201);
 },['admin']);
 if(method==='DELETE' && /^\/api\/programs\/[^/]+\/requirements\/[^/]+$/.test(path))return withAuth(req,env,async u=>{
  const programId=segments[2],requirementId=segments[4];
  const result=await env.DB.prepare('DELETE FROM program_requirements WHERE id=? AND program_id=?').bind(requirementId,programId).run();
  if(!result.meta.changes)return fail('Requirement not found',404);
  await audit(env,u.id,'program_requirement_removed',programId,{requirement_id:requirementId});return json({ok:true});
 },['admin']);
 if(method==='POST' && /^\/api\/programs\/[^/]+\/enroll$/.test(path))return withAuth(req,env,async u=>{
  const programId=segments[2];const exists=await env.DB.prepare('SELECT id FROM programs WHERE id=? AND active=1').bind(programId).first();
  if(!exists)return fail('Program not found',404);
  await env.DB.prepare('INSERT OR IGNORE INTO student_programs(student_id,program_id) VALUES (?,?)').bind(u.id,programId).run();
  await audit(env,u.id,'program_enrolled',programId);return json({ok:true});
 },['student']);
 if(method==='DELETE' && /^\/api\/programs\/[^/]+\/enroll$/.test(path))return withAuth(req,env,async u=>{
  const programId=segments[2];await env.DB.prepare('DELETE FROM student_programs WHERE student_id=? AND program_id=?').bind(u.id,programId).run();
  await audit(env,u.id,'program_unenrolled',programId);return json({ok:true});
 },['student']);
 // V4: reviewer worksheet. These flags are manually attested, NOT third-party verification.
 if(method==='GET' && /^\/api\/verification\/[^/]+$/.test(path))return withAuth(req,env,async u=>{
  const certId=segments[2];const cert=await env.DB.prepare(`SELECT c.id,c.title,c.issuer,c.credential_id,c.verification_url,c.earned_on,c.expires_on,c.status,c.proof_name,
   s.full_name AS student_name FROM certifications c JOIN users s ON s.id=c.student_id WHERE c.id=?`).bind(certId).first();
  if(!cert)return fail('Credential not found',404);
  const check=await env.DB.prepare('SELECT issuer_checked,identifier_checked,dates_checked,evidence_reviewed,reviewer_notes,checked_at FROM verification_checks WHERE certification_id=?').bind(certId).first();
  return json({cert,check:check||{issuer_checked:0,identifier_checked:0,dates_checked:0,evidence_reviewed:0,reviewer_notes:'',checked_at:null},notice:'Reviewer-recorded checks only; no external issuer or evidence validation occurs automatically.'});
 },['reviewer','admin']);
 if(method==='PUT' && /^\/api\/verification\/[^/]+$/.test(path))return withAuth(req,env,async u=>{
  const certId=segments[2],b=await parseJSON(req);
  const cert=await env.DB.prepare('SELECT id,status FROM certifications WHERE id=?').bind(certId).first();
  if(!cert)return fail('Credential not found',404);
  if(cert.status!=='pending')return fail('Only pending submissions have editable review checklists',409);
  const flags=['issuer_checked','identifier_checked','dates_checked','evidence_reviewed'];
  if(flags.some(k=>typeof b[k]!=='boolean'))return fail('Each checklist flag must be true or false');
  const notes=clean(b.reviewer_notes,1200);
  await env.DB.prepare(`INSERT INTO verification_checks(certification_id,issuer_checked,identifier_checked,dates_checked,evidence_reviewed,reviewer_notes,checked_by,checked_at)
   VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(certification_id) DO UPDATE SET
   issuer_checked=excluded.issuer_checked,identifier_checked=excluded.identifier_checked,
   dates_checked=excluded.dates_checked,evidence_reviewed=excluded.evidence_reviewed,
   reviewer_notes=excluded.reviewer_notes,checked_by=excluded.checked_by,checked_at=excluded.checked_at`)
   .bind(certId,...flags.map(k=>b[k]?1:0),notes,u.id,now()).run();
  await audit(env,u.id,'review_checklist_saved',certId,{completed:flags.filter(k=>b[k]).length});return json({ok:true});
 },['reviewer','admin']);
 // V4: Operational risk and oversight metrics, all aggregates are bounded and server-side.
 if(method==='GET' && path==='/api/operations')return withAuth(req,env,async u=>{
  const [status,aging,programs,expiring,recent,stale]=await Promise.all([
   env.DB.prepare('SELECT status,COUNT(*) AS total FROM certifications GROUP BY status').all(),
   env.DB.prepare(`SELECT c.id,c.title,c.issuer,c.created_at,s.full_name student_name,
    CAST(julianday('now')-julianday(c.created_at) AS INTEGER) AS days_waiting
    FROM certifications c JOIN users s ON s.id=c.student_id WHERE c.status='pending'
    ORDER BY c.created_at ASC LIMIT 80`).all(),
   env.DB.prepare(`SELECT p.id,p.title,COUNT(DISTINCT sp.student_id) AS students,COUNT(DISTINCT pr.id) AS requirements
    FROM programs p LEFT JOIN student_programs sp ON sp.program_id=p.id
    LEFT JOIN program_requirements pr ON pr.program_id=p.id
    WHERE p.active=1 GROUP BY p.id ORDER BY p.title LIMIT 80`).all(),
   env.DB.prepare(`SELECT c.title,c.expires_on,s.full_name student_name FROM certifications c
    JOIN users s ON s.id=c.student_id WHERE c.status='approved' AND c.expires_on IS NOT NULL
    AND c.expires_on<=date('now','+90 days') ORDER BY c.expires_on LIMIT 80`).all(),
   env.DB.prepare(`SELECT a.event,a.occurred_at,usr.full_name actor_name FROM audit_log a
    LEFT JOIN users usr ON usr.id=a.actor_id ORDER BY a.occurred_at DESC LIMIT 20`).all(),
   env.DB.prepare(`SELECT COUNT(*) AS total FROM certifications WHERE status='pending' AND created_at<datetime('now','-7 days')`).first()
  ]);
  return json({status:status.results,pending:aging.results,programs:programs.results,expiring:expiring.results,recent:recent.results,overdue_count:stale.total});
 },['reviewer','admin']);
 // V5: My workflow tasks: reviewer/admin only, admin sees all, reviewers their assignments and unassigned tasks.
 if(method==='GET'&&path==='/api/workflow/tasks')return withAuth(req,env,async u=>{
  const query=`SELECT t.id,t.title,t.priority,t.status,t.due_at,t.created_at,t.assigned_to,t.certification_id,
   c.title certification_title,student.full_name student_name,assignee.full_name assignee_name
   FROM workflow_tasks t JOIN certifications c ON c.id=t.certification_id
   JOIN users student ON student.id=c.student_id LEFT JOIN users assignee ON assignee.id=t.assigned_to
   WHERE t.status='open' ${admin(u)?'':'AND (t.assigned_to=? OR t.assigned_to IS NULL)'} ORDER BY
   CASE t.priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END,t.due_at LIMIT 100`;
  const stmt=env.DB.prepare(query);return json({items:(await (admin(u)?stmt:stmt.bind(u.id)).all()).results});
 },['reviewer','admin']);
 if(method==='PATCH'&&/^\/api\/workflow\/tasks\/[^/]+$/.test(path))return withAuth(req,env,async u=>{
  const id=segments[3],b=await parseJSON(req),action=clean(b.action,20);
  const task=await env.DB.prepare('SELECT * FROM workflow_tasks WHERE id=?').bind(id).first();if(!task)return fail('Task not found',404);
  if(!admin(u)&&task.assigned_to&&task.assigned_to!==u.id)return fail('Not your task',403);
  if(action==='claim'){
   const result=await env.DB.prepare("UPDATE workflow_tasks SET assigned_to=? WHERE id=? AND status='open' AND (assigned_to IS NULL OR assigned_to=?)").bind(u.id,id,u.id).run();
   if(!result.meta.changes)return fail('Task already assigned or closed',409);
  }else if(action==='complete'){
   if(!admin(u)&&task.assigned_to!==u.id)return fail('Claim the task before closing',403);
   await env.DB.prepare("UPDATE workflow_tasks SET status='completed',completed_at=? WHERE id=? AND status='open'").bind(now(),id).run();
  }else return fail('Unsupported task action');
  await audit(env,u.id,'task_'+action,id);return json({ok:true});
 },['reviewer','admin']);
 // V5: rule configuration; fixed safe events/actions instead of arbitrary code execution.
 if(method==='GET'&&path==='/api/workflow/rules')return withAuth(req,env,async u=>json({items:(await env.DB.prepare('SELECT * FROM workflow_rules ORDER BY created_at DESC LIMIT 100').all()).results}),['admin']);
 if(method==='POST'&&path==='/api/workflow/rules')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),event=clean(b.event,30),action=clean(b.action,20),priority=clean(b.priority,12),days=Number(b.days_due);
  if(!['submitted','needs_revision'].includes(event)||!['task','notify'].includes(action)||!['high','normal','low'].includes(priority)||!Number.isInteger(days)||days<1||days>30)return fail('Invalid workflow rule');
  const id=uuid();await env.DB.prepare('INSERT INTO workflow_rules (id,event,action,priority,days_due) VALUES (?,?,?,?,?)').bind(id,event,action,priority,days).run();
  await audit(env,u.id,'workflow_rule_created',id);return json({id},201);
 },['admin']);
 if(method==='PATCH'&&/^\/api\/workflow\/rules\/[^/]+$/.test(path))return withAuth(req,env,async u=>{
  const b=await parseJSON(req);if(typeof b.enabled!=='boolean')return fail('enabled must be boolean');
  const id=segments[3],change=await env.DB.prepare('UPDATE workflow_rules SET enabled=? WHERE id=?').bind(b.enabled?1:0,id).run();
  if(!change.meta.changes)return fail('Rule not found',404);await audit(env,u.id,'workflow_rule_updated',id,{enabled:b.enabled});return json({ok:true});
 },['admin']);
 // V5: session control; returns only metadata (never raw bearer secrets).
 if(method==='GET'&&path==='/api/security/sessions')return withAuth(req,env,async u=>json({items:(await env.DB.prepare('SELECT created_at,expires_at,token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 30').bind(u.id).all()).results.map(r=>({created_at:r.created_at,expires_at:r.expires_at,current:r.token_hash===u.token_hash}))}));
 if(method==='POST'&&path==='/api/security/revoke-others')return withAuth(req,env,async u=>{
  await env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').bind(u.id,u.token_hash).run();
  await audit(env,u.id,'other_sessions_revoked',u.id);return json({ok:true});
 });
 // V5: administrator-triggered demo accounts. No existing user or non-demo record deletion.
 // V5: One demo account per call: avoids multiple PBKDF2 hashes in a single Free Worker request.
 if(method==='POST'&&path==='/api/demo/account')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),which=clean(b.which,20);
  const specs={avery:['Avery Morgan','student','avery.demo@demo.example.test'],jordan:['Jordan Lee','student','jordan.demo@demo.example.test'],taylor:['Taylor Rivera','reviewer','taylor.demo@demo.example.test']};
  if(!Object.hasOwn(specs,which))return fail('Choose avery, jordan or taylor');
  const [name,role,email]=specs[which];
  if(await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first())return fail('This demo account already exists. Temporary passwords are not recoverable.',409);
  const pw='Demo-'+hex(crypto.getRandomValues(new Uint8Array(12)))+'z9',p=await hashPassword(pw),id=uuid();
  await env.DB.prepare('INSERT INTO users(id,email,full_name,role,password_hash,password_salt,password_iterations,must_change_password) VALUES(?,?,?,?,?,?,?,1)').bind(id,email,name,role,p.hash,p.salt,p.iterations).run();
  await audit(env,u.id,'demo_account_created',id,{role});
  return json({account:{name,email,role,temporary_password:pw},warning:'Copy this password privately now; it cannot be retrieved and must be changed on first login.'},201);
 },['admin']);
 // V5: executive reporting scoped to authorized staff, with no unredacted student export.
 if(method==='GET'&&path==='/api/executive')return withAuth(req,env,async u=>{
  const [overview,aging,programs]=await Promise.all([
   env.DB.prepare("SELECT COUNT(*) total, SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending FROM certifications").first(),
   env.DB.prepare("SELECT COUNT(*) total FROM workflow_tasks WHERE status='open' AND due_at<datetime('now')").first(),
   env.DB.prepare('SELECT COUNT(*) total FROM student_programs').first()
  ]);
  return json({total:overview.total,approved:overview.approved||0,pending:overview.pending||0,overdue_tasks:aging.total,enrollments:programs.total,disclaimer:'Demo metrics; approvals do not imply third-party issuer validation.'});
 },['reviewer','admin']);
 // V6: role-scoped global search. Search does not reveal records outside the caller's role.
 if(method==='GET'&&path==='/api/search')return withAuth(req,env,async u=>{
  const q=clean(new URL(req.url).searchParams.get('q'),80);
  if(q.length<2)return json({certifications:[],students:[],catalog:[],programs:[]});
  const like='%'+q.replace(/[\\%_]/g,m=>'\\'+m)+'%';
  const certSQL="SELECT c.id,c.title,c.issuer,c.status,c.student_id,u.full_name student_name FROM certifications c JOIN users u ON u.id=c.student_id WHERE (c.title LIKE ? ESCAPE '\\' OR c.issuer LIKE ? ESCAPE '\\' OR c.credential_id LIKE ? ESCAPE '\\')"+(reviewer(u)?'':' AND c.student_id=?')+' ORDER BY c.created_at DESC LIMIT 20';
  const certParams=reviewer(u)?[like,like,like]:[like,like,like,u.id];
  const certs=(await env.DB.prepare(certSQL).bind(...certParams).all()).results;
  const catalog=(await env.DB.prepare("SELECT id,title,issuer,category FROM catalog WHERE active=1 AND (title LIKE ? ESCAPE '\\' OR issuer LIKE ? ESCAPE '\\') LIMIT 20").bind(like,like).all()).results;
  const programs=(await env.DB.prepare("SELECT id,title,department FROM programs WHERE active=1 AND title LIKE ? ESCAPE '\\' LIMIT 15").bind(like).all()).results;
  const students=reviewer(u)?(await env.DB.prepare("SELECT id,full_name,email FROM users WHERE role='student' AND active=1 AND (full_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\') LIMIT 20").bind(like,like).all()).results:[];
  return json({certifications:certs,students,catalog,programs});
 });
 // V6: staff student directory; no passwords, tokens, or authentication metadata.
 if(method==='GET'&&path==='/api/students')return withAuth(req,env,async u=>{
  const items=(await env.DB.prepare("SELECT id,full_name,email,active,created_at FROM users WHERE role='student' ORDER BY full_name LIMIT 300").all()).results;
  return json({items});
 },['reviewer','admin']);
 // V6: Staff-only 360 profile; student cannot enumerate other students or retrieve private details.
 if(method==='GET'&&/^\/api\/students\/[0-9a-f-]+\/360$/.test(path))return withAuth(req,env,async u=>{
  const id=segments[2];
  const student=await env.DB.prepare("SELECT id,full_name,email,active,created_at FROM users WHERE id=? AND role='student'").bind(id).first();
  if(!student)return fail('Student not found',404);
  const [certs,goals,pathways,events]=await Promise.all([
    env.DB.prepare('SELECT id,title,issuer,status,earned_on,expires_on,created_at FROM certifications WHERE student_id=? ORDER BY created_at DESC LIMIT 100').bind(id).all(),
    env.DB.prepare('SELECT id,title,status,target_date FROM student_goals WHERE student_id=? ORDER BY created_at DESC LIMIT 30').bind(id).all(),
    env.DB.prepare('SELECT p.id,p.title,sp.joined_at FROM student_programs sp JOIN programs p ON p.id=sp.program_id WHERE sp.student_id=? LIMIT 30').bind(id).all(),
    env.DB.prepare("SELECT a.event,a.occurred_at FROM audit_log a WHERE a.actor_id=? AND a.event IN ('certification_created','goal_created','goal_updated','password_changed') ORDER BY a.occurred_at DESC LIMIT 15").bind(id).all()
  ]);
  await audit(env,u.id,'student_profile_viewed',id);
  return json({student,certifications:certs.results,goals:goals.results,programs:pathways.results,activity:events.results});
 },['reviewer','admin']);
 // V6: bounded filtered reporting with whitelisted dimensions; no raw PII in aggregate response.
 if(method==='GET'&&path==='/api/reports/studio')return withAuth(req,env,async u=>{
  const params=new URL(req.url).searchParams;
  const dimension=clean(params.get('group'),20)||'status';
  const status=clean(params.get('status'),30);
  if(!['status','issuer','month','program'].includes(dimension))return fail('Invalid report dimension');
  if(status&&!['pending','approved','rejected','needs_revision'].includes(status))return fail('Invalid status filter');
  let query,bind=[];
  if(dimension==='program'){
    query=`SELECT p.title label,COUNT(DISTINCT c.id) total FROM programs p LEFT JOIN student_programs sp ON sp.program_id=p.id LEFT JOIN certifications c ON c.student_id=sp.student_id ${status?'AND c.status=?':''} GROUP BY p.id ORDER BY total DESC LIMIT 30`;
    if(status)bind=[status];
  }else{
    const expr={status:'c.status',issuer:'c.issuer',month:'substr(c.created_at,1,7)'}[dimension];
    query=`SELECT ${expr} label,COUNT(*) total FROM certifications c ${status?'WHERE c.status=?':''} GROUP BY ${expr} ORDER BY total DESC LIMIT 40`;
    if(status)bind=[status];
  }
  const rows=(await env.DB.prepare(query).bind(...bind).all()).results;
  return json({group:dimension,status:status||'all',rows,disclaimer:dimension==='program'?'Program membership counts can overlap; each student may belong to multiple programs.':'Aggregate demonstration records only.'});
 },['reviewer','admin']);
 // V6: staff security dashboard. Does not reveal raw tokens, password hashes or IP data.
 if(method==='GET'&&path==='/api/security/center')return withAuth(req,env,async u=>{
  const [accounts,sessions,failed,events]=await Promise.all([
   env.DB.prepare('SELECT role,active,COUNT(*) total FROM users GROUP BY role,active').all(),
   env.DB.prepare("SELECT COUNT(*) total FROM sessions WHERE expires_at>?").bind(now()).first(),
   env.DB.prepare('SELECT COUNT(*) total FROM login_attempts WHERE count>=5').first(),
   env.DB.prepare("SELECT a.event,a.occurred_at,u.full_name actor FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id WHERE a.event IN ('login','password_changed','user_status_changed','other_sessions_revoked','bootstrap_admin','demo_account_created') ORDER BY a.occurred_at DESC LIMIT 35").all()
  ]);
  return json({accounts:accounts.results,active_sessions:sessions.total,high_attempt_keys:failed.total,events:events.results,disclaimer:'Prototype security overview. Not a SIEM, intrusion detection system, or institutional security audit.'});
 },['admin']);
 // V6: seed only recognized fictional demo users; idempotent and labeled, never deletes existing data.
 if(method==='POST'&&path==='/api/demo/scenario')return withAuth(req,env,async u=>{
  const b=await parseJSON(req),which=clean(b.which,20);
  const allowed={avery:'avery.demo@demo.example.test',jordan:'jordan.demo@demo.example.test'};
  if(!Object.hasOwn(allowed,which))return fail('Choose avery or jordan');
  const student=await env.DB.prepare("SELECT id FROM users WHERE email=? AND role='student' AND active=1").bind(allowed[which]).first();
  if(!student)return fail('Create this fictional student account first',404);
  const id='v6-demo-cert-'+which;
  const title=which==='avery'?'CompTIA Network+ (Demo)':'Cisco CCNA (Demo)';
  const status=which==='avery'?'pending':'needs_revision';
  const result=await env.DB.prepare(`INSERT OR IGNORE INTO certifications (id,student_id,title,issuer,credential_id,earned_on,status,proof_key,proof_name,proof_type,notes)
   VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(id,student.id,title,which==='avery'?'CompTIA':'Cisco','DEMO-ONLY-'+which,'2026-09-15',status,'demo:fictional','Fictional credential details only','demo-text','SYNTHETIC DATA — NOT A REAL CERTIFICATE').run();
  if(result.meta.changes){await audit(env,u.id,'demo_scenario_created',id,{synthetic:true});if(status==='pending')await applyWorkflow(env,id,'submitted',u.id);}
  return json({created:!!result.meta.changes,certification_id:id,message:result.meta.changes?'Fictional scenario created.':'Scenario already exists; no records overwritten.'});
 },['admin']);
 if(method==='GET'&&path==='/api/audit')return withAuth(req,env,async u=>json({items:(await env.DB.prepare('SELECT a.*,u.full_name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.occurred_at DESC LIMIT 100').all()).results}),['admin']);
 return fail('Not found',404);
}
export default {async fetch(req,env){
 const origin=req.headers.get('origin');const allowed=(env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim()).filter(Boolean);
 const cors=origin&&allowed.includes(origin)?{'access-control-allow-origin':origin,'vary':'Origin','access-control-allow-headers':'Authorization, Content-Type, X-Bootstrap-Token','access-control-allow-methods':'GET, POST, PUT, PATCH, DELETE, OPTIONS','access-control-max-age':'600'}:{};
 const headers={'x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-frame-options':'DENY','content-security-policy':"default-src 'none'; frame-ancestors 'none'",...cors};
 if(req.method==='OPTIONS')return new Response(null,{status:cors['access-control-allow-origin']?204:403,headers});
 const url=new URL(req.url);let response;
 try{response=await route(req,env,url.pathname.replace(/\/$/,'')||'/');}
 catch(e){console.error('API error:',e?.stack||e);response=e instanceof SyntaxError||e?.message?.startsWith('Invalid')||e?.message?.startsWith('Request too')||e?.message?.startsWith('Certification')||e?.message?.startsWith('Verification')||e?.message?.startsWith('New password')?fail(e.message):fail('Internal server error',500);}
 const h=new Headers(response.headers);for(const [k,v] of Object.entries(headers))h.set(k,v);
 return new Response(response.body,{status:response.status,headers:h});
}};
