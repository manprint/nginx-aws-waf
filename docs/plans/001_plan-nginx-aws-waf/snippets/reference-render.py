#!/usr/bin/env python3
# Throwaway prototype of the Go renderer: catalog -> modsec main.conf; verifies the output format.
import yaml, sys, os
cat = yaml.safe_load(open(os.environ.get('WAF_CATALOG', 'waf/catalog/rules.yaml')))
enabled_optional = set(sys.argv[1:])  # e.g. sqli anonip

def tline(ts):
    return ",".join(["t:none"] + [f"t:{t}" for t in (ts or [])])

def q(op):  # operator quoting: escape double quotes
    return op.replace('"', '\\"')

out = []
E = out.append
E('SecRuleEngine On')
E('SecRequestBodyAccess On')
E('SecRequestBodyLimit 8192')
E('SecRequestBodyNoFilesLimit 8192')
E('SecRequestBodyLimitAction ProcessPartial')
E('SecResponseBodyAccess Off')
E('SecPcreMatchLimit 100000')
E('SecPcreMatchLimitRecursion 100000')
E('SecUnicodeMapFile /etc/modsecurity.d/unicode.mapping 20127')
E('SecAuditEngine On')
E('SecAuditLogFormat JSON')
E('SecAuditLogType Serial')
E('SecAuditLog /tmp/audit.log')
E('SecAuditLogParts ABCFHZ')
init = ['setvar:tx.site=__default__', 'setvar:tx.mode=enforce', 'setvar:tx.default_action=allow',
        'setvar:tx.fail_pcre=closed', 'setvar:tx.fail_body=open']
E(f'SecRule &TX:site "@eq 0" "id:1900001,phase:1,pass,nolog,{",".join(init)}"')
E('SecAction "id:1900002,phase:1,pass,nolog,setvar:tx.term=0,setvar:tx.term_action=none,setvar:tx.awsterm=0,setvar:tx.fail=none,ctl:forceRequestBodyVariable=On"')
E('SecRule REQUEST_URI_RAW "@rx ^([^?#]*)" "id:1900003,phase:1,pass,nolog,capture,setvar:\'tx.raw_path=%{TX.1}\'"')
for gi, g in enumerate(cat['groups']):
    if g['optional'] and g['key'] not in enabled_optional:
        continue
    sv = [f"setvar:tx.inscope_{g['key']}=1", f"setvar:tx.grp_{g["key"]}={0 if g["optional"] else 1}"]
    sv += [f"setvar:tx.act_{r['id']}={r['default_action']}" for r in g['rules']]
    E(f'SecAction "id:{1900010+gi},phase:1,pass,nolog,{",".join(sv)}"')

for g in cat['groups']:
    k = g['key']
    if g['optional'] and k not in enabled_optional:
        continue
    gid = g['rules'][0]['id'] // 10000 * 10000  # e.g. 1200000
    E(f'# ---- {g["name"]}')
    E(f'SecRule TX:grp_{k} "@eq 0" "id:{gid+1},phase:2,pass,nolog,skipAfter:END_GRP_{k.upper()}"')
    for r in g['rules']:
        B = r['id']
        dets = r['detectors']
        if not dets:
            E(f'# {B} {r["name"]}: stub, no detector')
            continue
        assert len(dets) <= 7
        label = g['label_ns'] + r['label']
        for di, chain in enumerate(dets):
            logdata = f"a=%{{tx.act_{B}}};tb=%{{tx.term}};ab=%{{tx.awsterm}};sc=%{{tx.inscope_{k}}};v=%{{MATCHED_VAR_NAME}};x=%{{MATCHED_VAR}}"
            E(f'SecRule &TX:hit_{B} "@eq 0" "id:{B+di},phase:2,pass,nolog,auditlog,msg:\'AWSWAF {B}\','
              f'tag:\'awswaf-rule:{g["name"]}/{r["name"]}\',tag:\'awswaf-label:{label}\',logdata:\'{logdata}\',chain"')
            for li, link in enumerate(chain):
                last = li == len(chain) - 1
                acts = tline(link.get('t'))
                if last:
                    acts += f",setvar:tx.hit_{B}=1"
                else:
                    acts += ",chain"
                E(f'SecRule {link["vars"]} "{q(link["op"])}" "{acts}"')
        E(f'SecRule TX:hit_{B} "@eq 1" "id:{B+7},phase:2,pass,nolog,chain"')
        E(f'SecRule TX:inscope_{k} "@eq 1" "chain"')
        E(f'SecRule TX:term "@eq 0" "setvar:tx.lbl_{B}=1,setvar:tx.ns_{k}=1"')
        E(f'SecRule TX:hit_{B} "@eq 1" "id:{B+8},phase:2,pass,nolog,chain"')
        E(f'SecRule TX:inscope_{k} "@eq 1" "chain"')
        E(f'SecRule TX:act_{B} "@rx ^(?:block|allow)$" "chain"')
        E(f'SecRule TX:term "@eq 0" "setvar:tx.term={B},setvar:\'tx.term_action=%{{tx.act_{B}}}\'"')
        if r['default_action'] == 'block' and not g['optional']:
            E(f'SecRule TX:hit_{B} "@eq 1" "id:{B+9},phase:2,pass,nolog,chain"')
            E(f'SecRule TX:awsterm "@eq 0" "setvar:tx.awsterm={B}"')
    E(f'SecMarker END_GRP_{k.upper()}')

E('SecRule TX:MSC_PCRE_LIMITS_EXCEEDED "@eq 1" "id:1900800,phase:2,pass,nolog,setvar:tx.fail=pcre_limit"')
E('SecRule REQBODY_ERROR "@eq 1" "id:1900801,phase:2,pass,nolog,setvar:tx.fail=body_error"')
E("SecAction \"id:1900900,phase:2,pass,nolog,auditlog,msg:'AWSWAF_SUMMARY',logdata:'site=%{tx.site};mode=%{tx.mode};term=%{tx.term};ta=%{tx.term_action};aws=%{tx.awsterm};da=%{tx.default_action};fail=%{tx.fail}'\"")
E("SecRule TX:fail \"@streq pcre_limit\" \"id:1900910,phase:2,deny,status:500,nolog,auditlog,msg:'AWSWAF_FAIL',chain\"")
E('SecRule TX:fail_pcre "@streq closed" "t:none,chain"')
E('SecRule TX:mode "@streq enforce" "t:none"')
E("SecRule TX:term_action \"@streq block\" \"id:1900920,phase:2,deny,status:403,nolog,auditlog,msg:'AWSWAF_BLOCK',chain\"")
E('SecRule TX:mode "@streq enforce" "t:none"')
E("SecRule TX:term \"@eq 0\" \"id:1900930,phase:2,deny,status:403,nolog,auditlog,msg:'AWSWAF_DEFAULT_BLOCK',chain\"")
E('SecRule TX:default_action "@streq block" "t:none,chain"')
E('SecRule TX:mode "@streq enforce" "t:none"')
print("\n".join(out))
