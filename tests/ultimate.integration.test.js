import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import worker from '../worker/index.js';

const base = new URL('../migrations/', import.meta.url);
function makeEnv(){
  const sql = new DatabaseSync(':memory:');
  for(const name of ['0001_initial.sql','0002_advanced.sql','0003_enterprise.sql','0004_ultimate.sql','0005_experience.sql','0006_polish.sql','0007_student_management.sql']){
    sql.exec(readFileSync(new URL(name,base),'utf8'));
  }
  const DB={batch(statements){sql.exec('BEGIN');try{const outcomes=statements.map(x=>x.run());sql.exec('COMMIT');return outcomes;}catch(e){sql.exec('ROLLBACK');throw e;}},prepare(query){
    let values=[];
    return {
      bind(...args){values=args;return this},
      first(){return sql.prepare(query).get(...values)??null},
      all(){return {results:sql.prepare(query).all(...values)}},
      run(){return {meta:{changes:sql.prepare(query).run(...values).changes}}}
    };
  }};
  return {DB,BOOTSTRAP_TOKEN:'test-secret-only',ALLOWED_ORIGINS:'https://demo.github.io'};
}
async function request(env,method,path,token=null,data=undefined){
  const headers={origin:'https://demo.github.io'};
  if(token)headers.authorization='Bearer '+token;
  if(data!==undefined)headers['content-type']='application/json';
  if(path==='/api/setup')headers['x-bootstrap-token']='test-secret-only';
  const r=await worker.fetch(new Request('https://example.workers.dev'+path,{method,headers,body:data===undefined?undefined:JSON.stringify(data)}),env);
  const body=await r.json();
  return {status:r.status,body,headers:r.headers};
}

test('upgrade migration and authenticated v4 workflow',async()=>{
  const env=makeEnv(),password='StrongPrototype123';
  const setup=await request(env,'POST','/api/setup',null,{full_name:'System Administrator',email:'admin@example.test',password});
  assert.equal(setup.status,201,JSON.stringify(setup.body));
  const adminLogin=await request(env,'POST','/api/auth/login',null,{email:'admin@example.test',password});
  assert.equal(adminLogin.status,200,JSON.stringify(adminLogin.body));
  const admin=adminLogin.body.token;
  const studentNew=await request(env,'POST','/api/users',admin,{full_name:'Demo Student',email:'student@example.test',role:'student',password});
  assert.equal(studentNew.status,201,JSON.stringify(studentNew.body));
  const reviewerNew=await request(env,'POST','/api/users',admin,{full_name:'Demo Reviewer',email:'reviewer@example.test',role:'reviewer',password});
  assert.equal(reviewerNew.status,201,JSON.stringify(reviewerNew.body));
  const studentLogin=await request(env,'POST','/api/auth/login',null,{email:'student@example.test',password});
  const reviewerLogin=await request(env,'POST','/api/auth/login',null,{email:'reviewer@example.test',password});
  assert.equal(studentLogin.status,200);assert.equal(reviewerLogin.status,200);
  const student=studentLogin.body.token,rev=reviewerLogin.body.token;
  // Temporary passwords must be changed before accessing modules.
  assert.equal((await request(env,'GET','/api/programs',student)).status,403);
  assert.equal((await request(env,'POST','/api/auth/password',student,{current_password:password,new_password:'NewStudentPass123'})).status,200);
  assert.equal((await request(env,'POST','/api/auth/password',rev,{current_password:password,new_password:'NewReviewerPass123'})).status,200);
  const pathways=await request(env,'GET','/api/programs',student);
  assert.equal(pathways.status,200,JSON.stringify(pathways.body));
  assert.ok(pathways.body.programs.length>=3);
  assert.equal((await request(env,'POST','/api/programs',student,{title:'Forbidden Pathway'})).status,403);
  assert.equal((await request(env,'POST','/api/programs/path-network/enroll',student,{})).status,200);
  const enrolled=await request(env,'GET','/api/programs',student);
  assert.ok(enrolled.body.enrolled.includes('path-network'));
  const cert=await request(env,'POST','/api/certifications',student,{title:'CompTIA Network+',issuer:'CompTIA',earned_on:'2026-10-01'});
  assert.equal(cert.status,201,JSON.stringify(cert.body));
  const id=cert.body.id;
  assert.equal((await request(env,'GET','/api/verification/'+id,student)).status,403);
  const checks=await request(env,'PUT','/api/verification/'+id,rev,{issuer_checked:true,identifier_checked:true,dates_checked:true,evidence_reviewed:true,reviewer_notes:'Reviewed fictional submission claims only'});
  assert.equal(checks.status,200,JSON.stringify(checks.body));
  assert.equal((await request(env,'GET','/api/verification/'+id,rev)).body.check.issuer_checked,1);
  assert.equal((await request(env,'POST','/api/certifications/'+id+'/demo-evidence',student,{description:'Sample evidence details only'})).status,200);
  const decision=await request(env,'POST','/api/certifications/'+id+'/review',rev,{status:'approved',notes:'Fictional demo approval'});
  assert.equal(decision.status,200,JSON.stringify(decision.body));
  const updated=await request(env,'GET','/api/programs',student);
  assert.ok(updated.body.coverage.some(x=>x.program_id==='path-network'&&x.catalog_id==='seed-comptia-n'&&x.approved_count>0));
  const operations=await request(env,'GET','/api/operations',rev);
  assert.equal(operations.status,200,JSON.stringify(operations.body));
  assert.ok(operations.body.programs.some(x=>x.id==='path-network'&&x.students===1));
  assert.equal((await request(env,'GET','/api/operations',student)).status,403);
  assert.equal((await request(env,'PUT','/api/verification/'+id,rev,{issuer_checked:true,identifier_checked:true,dates_checked:true,evidence_reviewed:true})).status,409);
  const notify=await request(env,'GET','/api/notifications',student);
  assert.equal(notify.status,200);assert.ok(notify.body.items.some(x=>x.title.includes('approved')));
  assert.equal((await request(env,'GET','/api/health')).status,200);
});

test('v5 workflow tasks, role isolation, sessions, demo accounts and executive metrics',async()=>{
 const env=makeEnv(), password='ComplexPass123';
 assert.equal((await request(env,'POST','/api/setup',null,{full_name:'Demo Administrator',email:'owner@example.test',password})).status,201);
 const login=await request(env,'POST','/api/auth/login',null,{email:'owner@example.test',password});
 const admin=login.body.token;
 assert.equal((await request(env,'GET','/api/workflow/rules',admin)).body.items.length,1);
 const accounts=[];for(const which of ['avery','jordan','taylor']){const r=await request(env,'POST','/api/demo/account',admin,{which});assert.equal(r.status,201,JSON.stringify(r.body));accounts.push(r.body.account)}
 assert.equal(accounts.length,3);
 assert.equal((await request(env,'POST','/api/demo/account',admin,{which:'avery'})).status,409);
 const studentAccount=accounts.find(x=>x.role==='student'), reviewerAccount=accounts.find(x=>x.role==='reviewer');
 const studentLogin=await request(env,'POST','/api/auth/login',null,{email:studentAccount.email,password:studentAccount.temporary_password});
 assert.equal(studentLogin.status,200);
 const student=studentLogin.body.token;
 assert.equal((await request(env,'GET','/api/workflow/tasks',student)).status,403);
 assert.equal((await request(env,'POST','/api/auth/password',student,{current_password:studentAccount.temporary_password,new_password:'StudentNewPassword123'})).status,200);
 const reviewerLogin=await request(env,'POST','/api/auth/login',null,{email:reviewerAccount.email,password:reviewerAccount.temporary_password});
 const rev=reviewerLogin.body.token;
 assert.equal((await request(env,'POST','/api/auth/password',rev,{current_password:reviewerAccount.temporary_password,new_password:'ReviewerNewPassword123'})).status,200);
 const cert=await request(env,'POST','/api/certifications',student,{title:'Cisco CCNA',issuer:'Cisco',earned_on:'2026-10-01'});
 assert.equal(cert.status,201,JSON.stringify(cert.body));
 const tasks=await request(env,'GET','/api/workflow/tasks',rev);
 assert.equal(tasks.status,200,JSON.stringify(tasks.body));
 assert.equal(tasks.body.items.length,1);
 assert.equal((await request(env,'GET','/api/workflow/rules',student)).status,403);
 assert.equal((await request(env,'GET','/api/executive',rev)).status,200);
 assert.equal((await request(env,'GET','/api/executive',student)).status,403);
 const t=tasks.body.items[0];
 assert.equal((await request(env,'PATCH','/api/workflow/tasks/'+t.id,rev,{action:'claim'})).status,200);
 assert.equal((await request(env,'POST','/api/certifications/'+cert.body.id+'/demo-evidence',student,{description:'Fictional certification reference only'})).status,200);
 assert.equal((await request(env,'POST','/api/certifications/'+cert.body.id+'/review',rev,{status:'approved',notes:'No checklist'})).status,409);
 assert.equal((await request(env,'PUT','/api/verification/'+cert.body.id,rev,{issuer_checked:true,identifier_checked:true,dates_checked:true,evidence_reviewed:true,reviewer_notes:'Manual assessment'})).status,200);
 assert.equal((await request(env,'POST','/api/certifications/'+cert.body.id+'/review',rev,{status:'approved',notes:'Reviewed for demo'})).status,200);
 assert.equal((await request(env,'GET','/api/workflow/tasks',rev)).body.items.length,0);
 assert.equal((await request(env,'GET','/api/security/sessions',student)).status,200);
 assert.equal((await request(env,'POST','/api/security/revoke-others',student,{})).status,200);
});

test('v6 global search, Student 360 privacy, reporting, security and safe demo scenario',async()=>{
 const env=makeEnv(),pw='SecureDemoPassword123';
 assert.equal((await request(env,'POST','/api/setup',null,{full_name:'Test Admin',email:'admin-v6@example.test',password:pw})).status,201);
 const a=(await request(env,'POST','/api/auth/login',null,{email:'admin-v6@example.test',password:pw})).body.token;
 assert.ok(a);
 assert.equal((await request(env,'POST','/api/demo/account',a,{which:'avery'})).status,201);
 assert.equal((await request(env,'POST','/api/demo/account',a,{which:'taylor'})).status,201);
 const scenario=await request(env,'POST','/api/demo/scenario',a,{which:'avery'});
 assert.equal(scenario.status,200,JSON.stringify(scenario.body));
 assert.equal(scenario.body.created,true);
 assert.equal((await request(env,'POST','/api/demo/scenario',a,{which:'avery'})).body.created,false);
 const studentAccount=(await env.DB.prepare("SELECT id,email FROM users WHERE email='avery.demo@demo.example.test'").first());
 assert.ok(studentAccount);
 const dir=await request(env,'GET','/api/students',a);
 assert.equal(dir.status,200,JSON.stringify(dir.body));
 assert.ok(dir.body.items.some(x=>x.id===studentAccount.id));
 const profile=await request(env,'GET','/api/students/'+studentAccount.id+'/360',a);
 assert.equal(profile.status,200,JSON.stringify(profile.body));
 assert.ok(profile.body.certifications.some(x=>x.id===scenario.body.certification_id));
 assert.ok(!JSON.stringify(profile.body).includes('password_hash'));
 const search=await request(env,'GET','/api/search?q=Network',a);
 assert.equal(search.status,200,JSON.stringify(search.body));
 assert.ok(search.body.certifications.some(x=>x.id===scenario.body.certification_id));
 const report=await request(env,'GET','/api/reports/studio?group=status',a);
 assert.equal(report.status,200,JSON.stringify(report.body));
 assert.ok(report.body.rows.some(x=>x.label==='pending'));
 assert.equal((await request(env,'GET','/api/reports/studio?group=password_hash',a)).status,400);
 assert.equal((await request(env,'GET','/api/reports/studio?group=program',a)).status,200);
 const sec=await request(env,'GET','/api/security/center',a);
 assert.equal(sec.status,200,JSON.stringify(sec.body));
 assert.ok(!JSON.stringify(sec.body).includes('token_hash'));
 const temp=await request(env,'POST','/api/demo/account',a,{which:'jordan'});
 const sLogin=await request(env,'POST','/api/auth/login',null,{email:temp.body.account.email,password:temp.body.account.temporary_password});
 const student=sLogin.body.token;
 assert.equal((await request(env,'POST','/api/auth/password',student,{current_password:temp.body.account.temporary_password,new_password:'MoreSecureStudent12'})).status,200);
 assert.equal((await request(env,'GET','/api/students',student)).status,403);
 assert.equal((await request(env,'GET','/api/students/'+studentAccount.id+'/360',student)).status,403);
 assert.equal((await request(env,'GET','/api/reports/studio',student)).status,403);
 assert.equal((await request(env,'GET','/api/security/center',student)).status,403);
 assert.equal((await request(env,'POST','/api/demo/scenario',student,{which:'avery'})).status,403);
 const studentSearch=await request(env,'GET','/api/search?q=Network',student);
 assert.equal(studentSearch.status,200,JSON.stringify(studentSearch.body));
 assert.equal(studentSearch.body.students.length,0);
 assert.equal(studentSearch.body.certifications.length,0);
 const revAcc=await request(env,'POST','/api/demo/account',a,{which:'taylor'});
 assert.equal(revAcc.status,409);
 const r=await request(env,'POST','/api/users',a,{full_name:'Staff Reviewer',email:'staff@example.test',role:'reviewer',password:pw});
 assert.equal(r.status,201);
 const reviewer=(await request(env,'POST','/api/auth/login',null,{email:'staff@example.test',password:pw})).body.token;
 await request(env,'POST','/api/auth/password',reviewer,{current_password:pw,new_password:'ReviewerStrongPass123'});
 assert.equal((await request(env,'GET','/api/students',reviewer)).status,200);
 assert.equal((await request(env,'GET','/api/students/'+studentAccount.id+'/360',reviewer)).status,200);
 assert.equal((await request(env,'GET','/api/security/center',reviewer)).status,403);
});

test('v7 student account editing, sessions and reporting filters enforce permissions',async()=>{
 const env=makeEnv(),password='TestAccountPass123';
 assert.equal((await request(env,'POST','/api/setup',null,{full_name:'Administrator',email:'admin@test.example',password})).status,201);
 const admin=(await request(env,'POST','/api/auth/login',null,{email:'admin@test.example',password})).body.token;
 const created=await request(env,'POST','/api/users',admin,{full_name:'Avery Example',email:'avery@test.example',role:'student',password});
 assert.equal(created.status,201,JSON.stringify(created.body));
 const id=created.body.id;
 const other=await request(env,'POST','/api/users',admin,{full_name:'Jordan Example',email:'jordan@test.example',role:'student',password});
 assert.equal(other.status,201);
 const reviewer=await request(env,'POST','/api/users',admin,{full_name:'Staff Reviewer',email:'staff@test.example',role:'reviewer',password});
 assert.equal(reviewer.status,201);
 const rv=(await request(env,'POST','/api/auth/login',null,{email:'staff@test.example',password})).body.token;
 const st=(await request(env,'POST','/api/auth/login',null,{email:'avery@test.example',password})).body.token;
 assert.equal((await request(env,'POST','/api/auth/password',rv,{current_password:password,new_password:'ChangedReviewer123'})).status,200);
 assert.equal((await request(env,'POST','/api/auth/password',st,{current_password:password,new_password:'ChangedStudent123'})).status,200);
 const target='/api/students/'+id+'/profile';
 const payload={full_name:'Avery Updated',email:'avery.updated@test.example',department:'Technology',cohort:'Fall 2027',advisor:'Example Advisor',internal_reference:'SYNTHETIC-01',staff_notes:'Fictional sample only',active:true};
 assert.equal((await request(env,'PATCH',target,rv,payload)).status,403);
 assert.equal((await request(env,'PATCH',target,st,payload)).status,403);
 assert.equal((await request(env,'PATCH',target,admin,{...payload,email:'jordan@test.example'})).status,409);
 assert.equal((await request(env,'PATCH',target,admin,{...payload,full_name:'A'})).status,400);
 const saved=await request(env,'PATCH',target,admin,payload);assert.equal(saved.status,200,JSON.stringify(saved.body));
 const prof=await request(env,'GET','/api/students/'+id+'/360',rv);
 assert.equal(prof.status,200);assert.equal(prof.body.student.full_name,'Avery Updated');assert.equal(prof.body.student.profile.cohort,'Fall 2027');
 assert.equal((await request(env,'GET','/api/students/'+id+'/360',st)).status,403);
 const reset=await request(env,'POST','/api/students/'+id+'/reset-password',admin,{temporary_password:'TemporaryReset123'});
 assert.equal(reset.status,200,JSON.stringify(reset.body));
 assert.equal((await request(env,'GET','/api/auth/me',st)).status,401);
 const newLogin=await request(env,'POST','/api/auth/login',null,{email:'avery.updated@test.example',password:'TemporaryReset123'});
 assert.equal(newLogin.status,200);assert.equal(newLogin.body.user.must_change_password,true);
 assert.equal((await request(env,'PATCH',target,admin,{...payload,active:false})).status,200);
 assert.equal((await request(env,'GET','/api/auth/me',newLogin.body.token)).status,401);
 assert.equal((await request(env,'PATCH',target,admin,{...payload,active:true})).status,200);
 const query=await request(env,'GET','/api/reports/studio?group=issuer&from=2026-01-01&to=2026-12-31&issuer=CompTIA',rv);
 assert.equal(query.status,200,JSON.stringify(query.body));assert.ok(query.body.metrics);assert.ok(Array.isArray(query.body.trend));
 assert.equal((await request(env,'GET','/api/reports/studio?group=student',rv)).status,200);
 assert.equal((await request(env,'GET','/api/reports/studio?group=program&program=Network',rv)).status,200);
 assert.equal((await request(env,'GET','/api/reports/studio?from=2026-12-31&to=2026-01-01',rv)).status,400);
 assert.equal((await request(env,'GET','/api/reports/studio?group=issuer',st)).status,401);
});
