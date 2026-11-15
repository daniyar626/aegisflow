/*
 * Wazuh lab dataset for the AegisFlow MVP.
 *
 * SYNTHETIC DATA. Every host, user and address is invented. Public-looking
 * addresses come from the IPv4 documentation ranges (RFC 5737) and internal
 * ones from 10.20.0.0/16. Records follow the JSON shape that a Wazuh manager
 * writes to alerts.json, so the same code path handles real exports.
 *
 * build() is deterministic: it always returns the same 211 alerts.
 */
(function (root) {
  'use strict';
  var AF = root.AF = root.AF || {};

  var RULES = {
    '5710': { level: 5, description: 'sshd: Attempted login using a non-existent user', groups: ['syslog', 'sshd', 'authentication_failed', 'invalid_login'] },
    '5712': { level: 10, description: 'sshd: brute force trying to get access to the system. Non existent user.', groups: ['syslog', 'sshd', 'authentication_failures'] },
    '5716': { level: 5, description: 'sshd: authentication failed.', groups: ['syslog', 'sshd', 'authentication_failed'] },
    '5763': { level: 10, description: 'sshd: brute force trying to get access to the system. Authentication failed.', groups: ['syslog', 'sshd', 'authentication_failures'] },
    '5715': { level: 3, description: 'sshd: authentication success.', groups: ['syslog', 'sshd', 'authentication_success'] },
    '5501': { level: 3, description: 'PAM: Login session opened.', groups: ['pam', 'syslog', 'authentication_success'] },
    '5502': { level: 3, description: 'PAM: Login session closed.', groups: ['pam', 'syslog'] },
    '5402': { level: 3, description: 'Successful sudo to ROOT executed.', groups: ['syslog', 'sudo'] },
    '2902': { level: 7, description: 'New dpkg (Debian Package) installed.', groups: ['syslog', 'dpkg', 'config_changed'] },
    '5902': { level: 8, description: 'New user added to the system.', groups: ['syslog', 'adduser'] },
    '550': { level: 7, description: 'Integrity checksum changed.', groups: ['ossec', 'syscheck', 'syscheck_entry_modified', 'syscheck_file'] },
    '554': { level: 5, description: 'File added to the system.', groups: ['ossec', 'syscheck', 'syscheck_entry_added', 'syscheck_file'] },
    '31103': { level: 7, description: 'SQL injection attempt.', groups: ['web', 'accesslog', 'attack', 'sqlinjection'] },
    '31101': { level: 5, description: 'Web server 400 error code.', groups: ['web', 'accesslog', 'attack'] },
    '31151': { level: 10, description: 'Multiple web server 400 error codes from same source ip.', groups: ['web', 'accesslog', 'web_scan', 'recon'] },
    '60122': { level: 5, description: 'Logon Failure - Unknown user or bad password.', groups: ['windows', 'windows_security', 'authentication_failed'] },
    '510': { level: 7, description: 'Host-based anomaly detection event (rootcheck).', groups: ['ossec', 'rootcheck'] },
    '87105': { level: 12, description: 'VirusTotal: Alert - /tmp/.x/kworker - 41 engines detected this file', groups: ['virustotal'] },
    '1002': { level: 2, description: 'Unknown problem somewhere in the system.', groups: ['syslog', 'errors'] },
    '5104': { level: 8, description: 'Interface entered in promiscuous(sniffing) mode.', groups: ['syslog', 'linuxkernel', 'promisc'] }
  };

  var AGENTS = {
    'web-01': { id: '003', name: 'web-01', ip: '10.20.0.11' },
    'mail-01': { id: '004', name: 'mail-01', ip: '10.20.0.12' },
    'shop-web': { id: '005', name: 'shop-web', ip: '10.20.0.21' },
    'db-01': { id: '007', name: 'db-01', ip: '10.20.0.31' },
    'fileserver-01': { id: '009', name: 'fileserver-01', ip: '10.20.0.41' },
    'WS-FIN-07': { id: '012', name: 'WS-FIN-07', ip: '10.20.3.17' },
    'hr-laptop-12': { id: '015', name: 'hr-laptop-12', ip: '10.20.3.52' },
    'vpn-gw-01': { id: '002', name: 'vpn-gw-01', ip: '10.20.0.2' },
    'mail-02': { id: '006', name: 'mail-02', ip: '10.20.0.13' }
  };

  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var TZ_MS = 5 * 3600 * 1000; // lab clock is UTC+5
  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function makeBuilder(day) {
    var seq = 1000, out = [];
    function at(h, m, s) { return Date.UTC(2026, 10, day, h, m, s) - TZ_MS; }
    function local(ms) { return new Date(ms + TZ_MS); }
    function iso(ms) { return local(ms).toISOString().replace('Z', '+0500'); }
    function syslog(ms) {
      var d = local(ms);
      return MONTHS[d.getUTCMonth()] + ' ' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
    }
    function nginx(ms) {
      var d = local(ms);
      return pad(d.getUTCDate()) + '/' + MONTHS[d.getUTCMonth()] + '/' + d.getUTCFullYear() + ':' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + ' +0500';
    }
    function add(ms, host, ruleId, extra) {
      var r = RULES[ruleId];
      var rec = {
        timestamp: iso(ms),
        rule: { level: r.level, description: r.description, id: ruleId, groups: r.groups.slice() },
        agent: AGENTS[host],
        manager: { name: 'wazuh-lab' },
        id: Math.floor(ms / 1000) + '.' + (seq++)
      };
      for (var k in extra) rec[k] = extra[k];
      out.push(rec);
      return rec;
    }
    return { at: at, add: add, syslog: syslog, nginx: nginx, out: out };
  }

  function sshFail(b, ms, host, ip, user, invalid, composite, port) {
    var rule = invalid ? (composite ? '5712' : '5710') : (composite ? '5763' : '5716');
    b.add(ms, host, rule, {
      full_log: b.syslog(ms) + ' ' + host + ' sshd[' + (2200 + (port % 90)) + ']: Failed password for ' + (invalid ? 'invalid user ' : '') + user + ' from ' + ip + ' port ' + port + ' ssh2',
      decoder: { name: 'sshd' },
      data: invalid ? { srcip: ip, srcport: String(port), srcuser: user } : { srcip: ip, srcport: String(port), dstuser: user },
      location: '/var/log/auth.log'
    });
  }
  function sshOk(b, ms, host, ip, user, port) {
    b.add(ms, host, '5715', {
      full_log: b.syslog(ms) + ' ' + host + ' sshd[2291]: Accepted password for ' + user + ' from ' + ip + ' port ' + port + ' ssh2',
      decoder: { name: 'sshd' },
      data: { srcip: ip, srcport: String(port), dstuser: user },
      location: '/var/log/auth.log'
    });
  }

  function build() {
    var b = makeBuilder(14), i, ms, start;
    var guesses = ['admin', 'test', 'oracle', 'ubuntu', 'postgres', 'git', 'user', 'ftp', 'guest', 'support'];

    // A. Password guessing against web-01 that ends in a successful login (143 alerts).
    start = b.at(2, 14, 3);
    for (i = 0; i < 142; i++) {
      ms = start + Math.round(i * 2500);
      if (i < 40) sshFail(b, ms, 'web-01', '203.0.113.45', guesses[i % guesses.length], true, i % 8 === 7, 51000 + i);
      else sshFail(b, ms, 'web-01', '203.0.113.45', 'deploy', false, i % 8 === 7, 51000 + i);
    }
    sshOk(b, b.at(2, 20, 11), 'web-01', '203.0.113.45', 'deploy', 51190);

    // B. What happened on web-01 right after that login (3 alerts, no source address).
    ms = b.at(2, 23, 40);
    b.add(ms, 'web-01', '5902', {
      full_log: b.syslog(ms) + ' web-01 useradd[2377]: new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup, shell=/bin/bash',
      decoder: { name: 'useradd' }, data: { dstuser: 'svc-backup', uid: '1002' }, location: '/var/log/auth.log'
    });
    ms = b.at(2, 24, 5);
    b.add(ms, 'web-01', '550', {
      full_log: "File '/etc/sudoers' modified\nMode: scheduled\nChanged attributes: size,mtime,md5,sha1,sha256",
      decoder: { name: 'syscheck_integrity_changed' },
      syscheck: { path: '/etc/sudoers', event: 'modified', size_before: '755', size_after: '802', changed_attributes: ['size', 'mtime', 'md5', 'sha1', 'sha256'] },
      location: 'syscheck'
    });
    ms = b.at(2, 24, 31);
    b.add(ms, 'web-01', '554', {
      full_log: "File '/home/svc-backup/.ssh/authorized_keys' added\nMode: scheduled",
      decoder: { name: 'syscheck_new_entry' },
      syscheck: { path: '/home/svc-backup/.ssh/authorized_keys', event: 'added', size_after: '402' },
      location: 'syscheck'
    });

    // F. Three stray login attempts with common usernames (3 alerts).
    start = b.at(5, 40, 12);
    ['admin', 'test', 'oracle'].forEach(function (u, n) {
      sshFail(b, start + n * 9000, 'web-01', '192.0.2.77', u, true, false, 40210 + n);
    });

    // E. Someone in accounting mistypes a password three times (4 alerts).
    start = b.at(8, 52, 20);
    for (i = 0; i < 3; i++) sshFail(b, start + i * 7000, 'fileserver-01', '10.20.3.44', 'accounting', false, false, 60110 + i);
    sshOk(b, start + 31000, 'fileserver-01', '10.20.3.44', 'accounting', 60114);

    // D. Planned maintenance on db-01 (5 alerts, no source address).
    ms = b.at(9, 30, 2);
    b.add(ms, 'db-01', '5501', {
      full_log: b.syslog(ms) + ' db-01 login[1422]: pam_unix(login:session): session opened for user ops-admin by LOGIN(uid=0)',
      decoder: { name: 'pam' }, data: { dstuser: 'ops-admin' }, location: '/var/log/auth.log'
    });
    ms = b.at(9, 30, 40);
    b.add(ms, 'db-01', '5402', {
      full_log: b.syslog(ms) + ' db-01 sudo: ops-admin : TTY=tty1 ; PWD=/home/ops-admin ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y',
      decoder: { name: 'sudo' }, data: { srcuser: 'ops-admin', dstuser: 'root', command: '/usr/bin/apt-get upgrade -y' }, location: '/var/log/auth.log'
    });
    ['libssl3:amd64 3.0.13-0ubuntu3.5', 'openssl 3.0.13-0ubuntu3.5'].forEach(function (pkg, n) {
      var t = b.at(9, 31, 15 + n * 6);
      b.add(t, 'db-01', '2902', {
        full_log: '2026-11-14 09:31:' + pad(15 + n * 6) + ' status installed ' + pkg,
        decoder: { name: 'dpkg-decoder' }, data: { dpkg_status: 'installed', package: pkg.split(' ')[0] }, location: '/var/log/dpkg.log'
      });
    });
    ms = b.at(9, 36, 48);
    b.add(ms, 'db-01', '5502', {
      full_log: b.syslog(ms) + ' db-01 login[1422]: pam_unix(login:session): session closed for user ops-admin',
      decoder: { name: 'pam' }, data: { dstuser: 'ops-admin' }, location: '/var/log/auth.log'
    });

    // C. SQL injection probing against the shop site (14 alerts).
    start = b.at(11, 2, 10);
    var payloads = [
      "/product.php?id=1%27", "/product.php?id=1%27%20OR%20%271%27=%271", "/product.php?id=1%20UNION%20SELECT%20NULL--",
      "/product.php?id=1%20UNION%20SELECT%20NULL,NULL--", "/search.php?q=%27%20OR%201=1--", "/product.php?id=1%20AND%20SLEEP(5)--",
      "/login.php?user=admin%27--", "/product.php?id=-1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
      "/cart.php?item=1%27%20AND%20%271%27=%272"
    ];
    payloads.forEach(function (url, n) {
      var t = start + n * 11000;
      b.add(t, 'shop-web', '31103', {
        full_log: '198.51.100.23 - - [' + b.nginx(t) + '] "GET ' + url + ' HTTP/1.1" 404 162 "-" "sqlmap/1.8"',
        decoder: { name: 'web-accesslog' }, data: { srcip: '198.51.100.23', protocol: 'GET', url: url, id: '404' }, location: '/var/log/nginx/access.log'
      });
    });
    ['/admin/', '/.env', '/wp-login.php'].forEach(function (url, n) {
      var t = start + 104000 + n * 5000;
      b.add(t, 'shop-web', '31101', {
        full_log: '198.51.100.23 - - [' + b.nginx(t) + '] "GET ' + url + ' HTTP/1.1" 404 162 "-" "sqlmap/1.8"',
        decoder: { name: 'web-accesslog' }, data: { srcip: '198.51.100.23', protocol: 'GET', url: url, id: '404' }, location: '/var/log/nginx/access.log'
      });
    });
    [121000, 133000].forEach(function (offset) {
      var t = start + offset;
      b.add(t, 'shop-web', '31151', {
        full_log: '198.51.100.23 - - [' + b.nginx(t) + '] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "sqlmap/1.8"',
        decoder: { name: 'web-accesslog' }, data: { srcip: '198.51.100.23', protocol: 'GET', url: '/phpmyadmin/', id: '404' }, location: '/var/log/nginx/access.log'
      });
    });

    // G. A finance workstation keeps failing to log in from an internal address (12 alerts).
    start = b.at(12, 15, 0);
    for (i = 0; i < 12; i++) {
      ms = start + i * 30000;
      b.add(ms, 'WS-FIN-07', '60122', {
        full_log: 'Security: 4625: An account failed to log on. Account Name: fin-svc. Source Network Address: 10.20.3.88. Failure Reason: Unknown user name or bad password.',
        decoder: { name: 'windows_eventchannel' },
        data: { win: { system: { eventID: '4625', channel: 'Security', computer: 'WS-FIN-07' }, eventdata: { targetUserName: 'fin-svc', ipAddress: '10.20.3.88', logonType: '3', status: '0xc000006d' } } },
        location: 'EventChannel'
      });
    }

    // I. Password guessing from an address no reputation list knows (20 alerts).
    start = b.at(14, 10, 5);
    for (i = 0; i < 20; i++) {
      sshFail(b, start + i * 9000, 'mail-01', '198.51.100.200', i % 2 ? 'postmaster' : 'info', false, i % 8 === 7, 33400 + i);
    }

    // H. A flagged file on an HR laptop (2 alerts, no source address).
    ms = b.at(15, 2, 44);
    b.add(ms, 'hr-laptop-12', '510', {
      full_log: "File '/tmp/.x/kworker' is owned by root and has written permissions to anyone.",
      decoder: { name: 'rootcheck' }, data: { title: 'File is owned by root and has written permissions to anyone.', file: '/tmp/.x/kworker' }, location: 'rootcheck'
    });
    ms = b.at(15, 3, 20);
    b.add(ms, 'hr-laptop-12', '87105', {
      full_log: '{"virustotal": {"found": 1, "malicious": 1, "source": {"file": "/tmp/.x/kworker"}, "positives": 41, "total": 70}}',
      decoder: { name: 'json' },
      data: { virustotal: { found: '1', malicious: '1', positives: '41', total: '70', source: { file: '/tmp/.x/kworker', sha1: '5d1f0e0c2a8b4f9de7c1a3b65f0e9d2c4b7a6e81' } }, integration: 'virustotal' },
      location: 'virustotal'
    });

    // J. Low-level noise with no pattern (4 alerts), then one unexplained high-level alert.
    start = b.at(16, 2, 11);
    for (i = 0; i < 4; i++) {
      ms = start + i * 300000;
      b.add(ms, 'db-01', '1002', {
        full_log: b.syslog(ms) + " db-01 systemd[1]: report-export.service: Failed with result 'exit-code'.",
        decoder: { name: 'systemd' }, location: '/var/log/syslog'
      });
    }
    ms = b.at(18, 45, 9);
    b.add(ms, 'db-01', '5104', {
      full_log: b.syslog(ms) + ' db-01 kernel: [90412.551] device eth0 entered promiscuous mode',
      decoder: { name: 'kernel' }, location: '/var/log/kern.log'
    });

    return b.out;
  }

  /* A second, smaller export used for the import demo (30 alerts on the next day). */
  function buildImportSample() {
    var b = makeBuilder(15), i, start;
    start = b.at(3, 5, 10);
    for (i = 0; i < 26; i++) {
      sshFail(b, start + i * 4000, 'vpn-gw-01', '203.0.113.99', i % 3 ? 'root' : 'vpnuser', false, i % 8 === 7, 44100 + i);
    }
    start = b.at(9, 12, 0);
    for (i = 0; i < 3; i++) sshFail(b, start + i * 6000, 'mail-02', '10.20.3.61', 'reception', false, false, 50110 + i);
    sshOk(b, start + 26000, 'mail-02', '10.20.3.61', 'reception', 50115);
    return b.out;
  }

  var api = { build: build, buildImportSample: buildImportSample, alertCount: 211 };
  AF.demo = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
