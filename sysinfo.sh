#!/bin/bash
echo "dss:hostname: $(hostname)"
echo "dss:date: $(date -u)"
echo "dss:shell: $SHELL"
echo "dss:dates: $(date -u +%s)"
echo "dss:uptimes:$([ -f /proc/uptime ] && cat /proc/uptime | awk '{print $1}')"
echo "dss:uptime: $(uptime)"
echo "dss:kernel: $(uname -a)"
echo "dss:bittedness: $(getconf LONG_BIT)"
df -m | awk '{print "dss:dfm:" $0}'
df -m | egrep '/dev/root | /$' | head -n 1 | awk '{if($4<1) {print "RET:DISKLOW:OUT:" $4;} else if($4<500) {print "RET:DISKLOW:LOW:" $4;}}'
dmesg -T | egrep 'oom_reaper|Out of memory:|invoked oom-killer' | awk '{print "RET:OOM:"$0}' | tail
dmesg -T | egrep -qai 'waiting for ip6gre0 to become free' && echo "RET:IP6GRE0ERROR:$(uname -a)"

[ -f /var/log/memmon.txt ] && [ $(egrep 'average: ' /var/log/memmon.txt  | egrep -v 'average: [012]\.' | wc -l ) -gt 6  ] && egrep --before-context 1  'average: [^01].' /var/log/memmon.txt | grep -v -- '--' | tail -n 6 | awk '{print "RET:HIGHLOAD:"$0}'

echo "dss:Redhat-release: $([ ! -f /etc/redhat-release ] && echo 'NA'; [ -f /etc/redhat-release ] && cat /etc/redhat-release)"
echo "dss:Debian-version: $([ ! -f /etc/debian_version ] && echo 'NA'; [ -f /etc/debian_version ] && cat /etc/debian_version)"
if [ -x /usr/bin/lsb_release ] || [ -x /bin/lsb_release ] ; then    
  echo "dss:distroinfo: $(lsb_release -a 2>/dev/null | grep -i description)" 
elif [ -f /etc/debian_version ]; then
  echo "dss:distroinfo: DEBIAN $(cat /etc/debian_version)" 
elif [ -f /etc/redhat-release ]; then
  echo "dss:distroinfo: REDHAT $(cat /etc/redhat-release)"
else echo "dss:distroinfo: NA"; fi
ps ax | awk '{print "dss:process: " $5 " " $6 " " $7 " " $8 " " $9}' | egrep -v '^dss:process: \[|COMMAND|init' | uniq
ps axo stat,pid,cp,pcpu,comm,cmd 2>&1  | grep -v '^STAT'| sort -k 3 | awk '{if($3>100) {x= ($3 < 300 ? "MID:" : "HIGH:"); print "RET:HIGHCPU:" ($3 < 300 ? "MID:" : "HIGH:")  $0;}}'

eximvuln=N
ps ax | awk '{print "dss:process: " $5 " " $6 " " $7 " " $8 " " $9}' | egrep -v '^dss:process: \[|COMMAND|init' | grep -qai '[e]xim' && eximvuln="?" 
echo "dss:isvulnerable:beforefix: CVE-2021-27216${eximvuln}"

which dpkg 2>&1 >/dev/null && dpkg -l | grep exim | awk '{print "RET:EXIM:DPKG:" $0}'
which rpm 2>&1 >/dev/null && rpm -qa | grep exim | awk '{print "RET:EXIM:RPM:" $0}'


function webminchecks() {
# http://www.webmin.com/exploit.html

webmindir=
for webmindir in '/usr/libexec/webmin' '/usr/share/webmin' ''; do  
  [ -f "$webmindir/version" ] && echo "RET:WEBMINVERSION:$(cat "$webmindir/version")" && break
done
 
[ -z "$webmindir" ] && echo "RET:NOWEBMIN" && return 0
# vulnerable versions per https://medium.com/@knownsec404team/backdoor-exploration-of-webmin-remote-code-execution-vulnerabilities-cve-2019-15107-55234c0bd486
# 1.920 1.910 1.900 1.890
# Version 1.890 is vulnerable in a default install and should be upgraded immediately - other versions are only vulnerable if changing of expired passwords is enabled, which is not the case by default.

# non vulnerable version:
# 1.930 and later, 1.880 and earlier
egrep -qai '1.920|1.910|1.900|1.890' "$webmindir/version" && echo "RET:WEBMIN:EXPLOITABLEVERSION"
egrep -qai '1.890' "$webmindir/version" && echo "RET:WEBMIN:EXPLOITABLEVERSIONBYDEFAULT"

echo "RET:WEMINDATE:$(stat "$webmindir/version" | grep Change | awk '{print $2}')"

[ -f /etc/webmin/miniserv.conf ]  && echo "RET:WEBMINPASSWD_MODE:$(cat /etc/webmin/miniserv.conf | grep passwd_mode)"
[ -d  /opt/ng99 ] && echo "RET:WEBMINEXPLOITFILE: /opt/ng99"

# At some time in April 2018, the Webmin development build server was exploited and a vulnerability added to the password_change.cgi script. Because the timestamp on the file was set back, it did not show up in any Git diffs. 
# Original issue in the Webmin 1.890 release 2018-04
# Expired password issue in Webmin 1.900 release 2018-07
# Fixed in Webmin version 1.930 2019-08-17
# 
[ -f "$webmindir/password_change.cgi" ] && grep --fixed-strings '},qx/' "$webmindir/password_change.cgi" && echo "RET:WEBMIN:SOURCEFORGEBACKDOOR:https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/unix/webapp/webmin_backdoor.md"

return 0  
}

webminchecks
