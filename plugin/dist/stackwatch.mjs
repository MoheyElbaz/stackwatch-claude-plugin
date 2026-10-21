#!/usr/bin/env node
// stackwatch, GPL-3.0-or-later, https://github.com/MoheyElbaz/stackwatch-claude-plugin (bundled packages and their licenses: THIRD_PARTY_NOTICES.txt)
import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);
import{a as p,b as C,c as g,d as w,e as L,f as N,g as l,h as P,i as A,j as u,k,l as $,m as v,n as T,o as D,p as O,q as I,r as M,s as R,t as H,u as U,v as F,w as _,x as B,y as W}from"./chunks/chunk-C6W6SYUG.mjs";import"./chunks/chunk-QW3LZR5O.mjs";import{parseArgs as ut}from"node:util";import{appendFileSync as X,mkdirSync as Z}from"node:fs";var tt=60*6e4,et=2e4;async function q(e=Date.now(),t=()=>v({timeoutMs:6e3,quick:!0})){try{let o=u();if(!Object.keys(o.stacks).length)return null;(!o.lastRefresh||e-Date.parse(o.lastRefresh)>tt)&&await Promise.race([t().catch(i=>V(`refresh: ${i.message}`)),new Promise(i=>setTimeout(i,et).unref())]);let s=u(),n=w(s.items,i=>$(s,i)),r=n.filter(i=>!i.top.read),a=n.length-r.length;if(!n.length)return null;if(!r.length)return{systemMessage:`stackwatch: ${a} security alert${a===1?"":"s"} read but still open. /stackwatch:check`};let m=new Map(A().sources.map(i=>[i.id,i.name]));return{systemMessage:rt(r,a),hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:["<stackwatch-alerts>",`stackwatch has ${r.length} unread security alert(s) for the user's projects (at or above each project's alert level).`,"Mention them briefly at the start of your reply and offer the security-check skill for details and fixes. They stay unread until the user marks them read.",C,"",N(r,i=>m.get(i)??i,6),"</stackwatch-alerts>"].join(`
`)}}}catch(o){return V(`hook: ${o.stack??o}`),null}}function rt(e,t){let o=e[0].top,s=o.matches.find(a=>!a.dev)??o.matches[0],n=`${o.level.toUpperCase()}${o.exploited?", exploited":""}: ${s.project} \xB7 ${s.component} ${s.version}${s.fixed?` \u2192 ${s.fixed}`:""}`,r=L(e);return`stackwatch: ${e.length} unread security alert${e.length===1?"":"s"} (${r} thing${r===1?"":"s"} to fix)${t?`, +${t} read but open`:""}. ${n}. /stackwatch:check`}function V(e){try{Z(l(),{recursive:!0,mode:448}),X(P(),`[${new Date().toISOString()}] ${e}
`,{mode:384})}catch{}}import{spawn as ot,spawnSync as y}from"node:child_process";import{existsSync as nt,mkdirSync as G,rmSync as st,writeFileSync as it}from"node:fs";import{homedir as J,platform as j}from"node:os";import{join as f}from"node:path";var b="dev.stackwatch.check";async function K(){if(!u().settings?.notifications)return"Notifications are off. Turn them on with `stackwatch notifications on`.";let e=await v({timeoutMs:2e4}),t=u(),o=w(t.items,i=>$(t,i)).filter(i=>!i.top.read&&!i.items.some(d=>d.notifiedAt));if(!o.length)return`No new alerts.${e.problems.length?` (${e.problems.length} source problem(s))`:""}`;let s=at(o);ct(o.length===1?x(o[0]):`${o.length} new security alerts. ${x(o[0])}`);let n=t.settings?.notifyCommand,r="";n&&(r=await lt(n,s));let a=new Date().toISOString(),m=new Set(o.flatMap(i=>i.items.map(d=>d.id)));return k(i=>{i.items=i.items.map(d=>m.has(d.id)?{...d,notifiedAt:a}:d)}),`Announced ${o.length} new alert${o.length===1?"":"s"}${r}.

${s}`}function x(e){let t=e.top.matches.find(o=>!o.dev)??e.top.matches[0];return`${e.top.level.toUpperCase()}${e.top.exploited?" (exploited)":""}: ${t?`${t.project} \xB7 ${t.component} ${t.version}${t.fixed?` \u2192 ${t.fixed}`:""}`:g(e.top.title,80)}`}function at(e){return e.map(t=>`${x(t)}
  ${g(t.top.title)}
  ${[...t.top.cves.slice(0,3),t.top.url].join(" \xB7 ")}`).join(`

`)}function ct(e){j()==="darwin"?y("osascript",["-e","on run argv","-e",'display notification (item 1 of argv) with title "stackwatch" sound name "Basso"',"-e","end run",g(e,200)]):j()==="linux"&&y("notify-send",["stackwatch",g(e,200)])}function lt(e,t){return new Promise(o=>{let s=ot("sh",["-c",e],{stdio:["pipe","ignore","pipe"]}),n="";s.stderr.on("data",r=>n+=r),s.on("error",r=>o(` (notify command failed: ${r.message})`)),s.on("close",r=>o(r===0?" and sent it with your notify command":` (notify command exited ${r}: ${n.trim().slice(0,200)})`)),s.stdin.end(`stackwatch: new security alerts

${t}
`)})}function Y(e){return k(t=>(t.settings={...t.settings},e?t.settings.notifyCommand=e:delete t.settings.notifyCommand,e?`New alerts will also be piped to: ${e}`:"Notify command removed; desktop notifications only."))}function z(e,t){if(e==="status"){let o=u(),s=!!o.settings?.notifications;return[`Notifications are ${s?"on":"off"}.`,s?S("status",t):"Turn them on with `stackwatch notifications on` (hourly check, desktop notification).",o.settings?.notifyCommand?`Notify command: ${o.settings.notifyCommand}`:'No notify command (set one with `stackwatch notify-command "<cmd>"`).'].join(`
`)}return k(o=>{o.settings={...o.settings,notifications:e==="on"}}),e==="on"?`Notifications on. ${S("install",t)}`:`Notifications off. ${S("remove",t)}`}var h=()=>f(J(),"Library","LaunchAgents",`${b}.plist`);function S(e,t){let o=`0 * * * * ${process.execPath} ${t} notify >> ${f(l(),"schedule.log")} 2>&1`;if(j()!=="darwin")return e==="status"?"Scheduling is set up by you on this system. Add this line with `crontab -e`:\n"+o:`On this system, add (or remove) this line with \`crontab -e\`:
${o}`;let s=`gui/${process.getuid?.()??501}`;if(e==="status")return y("launchctl",["print",`${s}/${b}`],{encoding:"utf8"}).status===0?`Scheduled: checks every hour (${h()}).`:"Not scheduled. Run `stackwatch schedule install`.";if(y("launchctl",["bootout",`${s}/${b}`]),e==="remove")return nt(h())&&st(h()),"Hourly check removed.";G(f(J(),"Library","LaunchAgents"),{recursive:!0}),G(l(),{recursive:!0,mode:448});let n=a=>a.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");it(h(),`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${b}</string>
  <key>ProgramArguments</key>
  <array><string>${n(process.execPath)}</string><string>${n(t)}</string><string>notify</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>${n(f(l(),"schedule.log"))}</string>
  <key>StandardErrorPath</key><string>${n(f(l(),"schedule.log"))}</string>
</dict>
</plist>
`);let r=y("launchctl",["bootstrap",s,h()],{encoding:"utf8"});return r.status!==0?`Wrote ${h()} but launchctl refused it: ${r.stderr.trim()}`:`Scheduled: every hour, new alerts become a desktop notification${u().settings?.notifyCommand?" and go to your notify command":""}. Log: ${f(l(),"schedule.log")}`}var E="0.1.1",Q=`stackwatch ${E}: security news and alerts for the tech your projects run on

  alerts [project] [--read]               unread critical/high alerts (--read: also read but still open)
  news [--all] [--source id] [--project p] [--product p] [--min level] [--limit n]
                                          everything the sources said, unread first
  read <id...> | --alerts | --source id | --all  [--note text]
                                          mark items read
  unread <id...>                          mark items unread
  refresh                                 read every source now
  sources                                 list the sources (sources.json + ~/.stackwatch/sources.json)

  init [path] [--name n] [--exclude a,b] [--ssh user@host] [--port n] [--identity key] [--level l]
                                          register a project: its files, its server's versions, a first check
  update [project]                        re-scan files and server, show what changed, check again
  add <project> <name> <version> --product p [--note t]
                                          add what neither can see, by hand
  remove <project> <name>                 remove one added by hand
  level <critical|high|medium|low> [project]
                                          lowest level that raises an alert (default high)
  list                                    projects with their risk

  notifications on|off|status             alerts outside Claude, off by default: on = hourly check + desktop notification
  notify-command "<cmd>" | --clear        with notifications on, also pipe new alerts to your command ("mail -s stackwatch you@example.com")
  notify                                  what the hourly check runs: refresh, announce each new alert once

  hook                                    Claude Code SessionStart hook
  mcp                                     run the MCP server on stdio

Levels: ${p.join(", ")}. Data: ~/.stackwatch/data.json (STACKWATCH_HOME to move it).`;async function dt(e){let{values:t,positionals:o}=ut({args:e,allowPositionals:!0,options:{name:{type:"string"},exclude:{type:"string"},product:{type:"string"},note:{type:"string"},ssh:{type:"string"},port:{type:"string"},identity:{type:"string"},level:{type:"string"},source:{type:"string"},project:{type:"string"},min:{type:"string"},limit:{type:"string"},all:{type:"boolean"},alerts:{type:"boolean"},read:{type:"boolean"},clear:{type:"boolean"},help:{type:"boolean",short:"h"},version:{type:"boolean",short:"v"}}}),[s,...n]=o;if(t.version)return c(E);if(t.help||!s||s==="help")return c(Q);switch(s){case"alerts":{let r=await U({project:n[0],includeRead:t.read});return c(r.text),r.items.some(a=>!a.read)?2:0}case"news":{let r=t.min;if(r&&!p.includes(r))throw new Error(`--min must be one of ${p.join(", ")}`);return c(await F({all:t.all,source:t.source,project:t.project,product:t.product,min:r,limit:t.limit?Number(t.limit):void 0}))}case"read":return c(_({ids:n,all:t.all,source:t.source,alerts:t.alerts,note:t.note}));case"unread":if(!n.length)throw new Error("usage: stackwatch unread <id...>");return c(B(n));case"refresh":return c(await H());case"sources":return c(W());case"init":{let r=t.level;if(r&&!p.includes(r))throw new Error(`--level must be one of ${p.join(", ")}`);return c(await T(n[0]??process.cwd(),{name:t.name,exclude:t.exclude?.split(",").map(a=>a.trim()).filter(Boolean),...t.ssh?{ssh:{target:t.ssh,...t.port?{port:Number(t.port)}:{},...t.identity?{identity:t.identity}:{}}}:{},...r?{alertLevel:r}:{}}))}case"update":return c(await D(n[0]));case"level":if(!n[0])throw new Error("usage: stackwatch level <critical|high|medium|low> [project]");return c(M(n[0],n[1]));case"add":{let[r,a,m]=n;if(!r||!a||!m)throw new Error("usage: stackwatch add <project> <name> <version> --product p");return c(O(r,{name:a,version:m,...t.product?{product:t.product}:{},...t.note?{note:t.note}:{}}))}case"remove":if(!n[0]||!n[1])throw new Error("usage: stackwatch remove <project> <name>");return c(I(n[0],n[1]));case"list":return c(R());case"notify":return c(await K());case"notify-command":if(!t.clear&&!n[0])throw new Error('usage: stackwatch notify-command "<command>" | --clear');return c(Y(t.clear?null:n.join(" ")));case"notifications":{let r=n[0]??"status";if(!["on","off","status"].includes(r))throw new Error("usage: stackwatch notifications on|off|status");return c(z(r,process.argv[1]))}case"hook":{let r=await q();r&&process.stdout.write(JSON.stringify(r)),process.exit(0)}case"mcp":{let{startMcpServer:r}=await import("./chunks/mcp-BAXFWYUQ.mjs");return await r(E),-1}default:throw new Error(`unknown command "${s}"

${Q}`)}}function c(e){return process.stdout.write(e.endsWith(`
`)?e:`${e}
`),0}dt(process.argv.slice(2)).then(e=>{e>=0&&(process.exitCode=e)},e=>{process.stderr.write(`stackwatch: ${e.message}
`),process.exitCode=1});
