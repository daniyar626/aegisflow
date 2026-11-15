/*
 * AegisFlow address intelligence: classifies IPv4 addresses and looks them up
 * in a small reputation set that ships with the MVP.
 *
 * The lists below are a DEMO set. They only contain addresses from the three
 * IPv4 documentation ranges (RFC 5737), so no real address is ever accused.
 * A production build would replace lookup() with a server-side call to a
 * licensed reputation feed.
 */
(function (root) {
  'use strict';
  var AF = root.AF = root.AF || {};

  var LISTS = [
    {
      id: 'demo-ssh-bruteforce',
      name: { en: 'Demo SSH brute-force blocklist', kk: 'SSH құпиясөзін іріктеушілердің демо-тізімі' },
      updated: '2026-11-10',
      ips: ['203.0.113.45', '203.0.113.99']
    },
    {
      id: 'demo-abuse-reports',
      name: { en: 'Demo abuse reports list', kk: 'Шағымдар бойынша демо-тізім' },
      updated: '2026-11-12',
      ips: ['203.0.113.45']
    },
    {
      id: 'demo-web-attackers',
      name: { en: 'Demo web attack sources list', kk: 'Веб-шабуыл көздерінің демо-тізімі' },
      updated: '2026-11-09',
      ips: ['198.51.100.23']
    },
    {
      id: 'demo-scanners',
      name: { en: 'Demo internet scanners list', kk: 'Интернет-сканерлердің демо-тізімі' },
      updated: '2026-11-11',
      ips: ['192.0.2.77']
    }
  ];

  function octets(ip) {
    if (typeof ip !== 'string') return null;
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
    if (!m) return null;
    var o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
    for (var i = 0; i < 4; i++) if (o[i] > 255) return null;
    return o;
  }

  /* Returns one of: private, loopback, doc, public, ipv6, invalid. */
  function classifyIp(ip) {
    if (typeof ip === 'string' && ip.indexOf(':') !== -1) return 'ipv6';
    var o = octets(ip);
    if (!o) return 'invalid';
    if (o[0] === 127) return 'loopback';
    if (o[0] === 10) return 'private';
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
    if (o[0] === 192 && o[1] === 168) return 'private';
    if (o[0] === 169 && o[1] === 254) return 'private';
    if (o[0] === 192 && o[1] === 0 && o[2] === 2) return 'doc';
    if (o[0] === 198 && o[1] === 51 && o[2] === 100) return 'doc';
    if (o[0] === 203 && o[1] === 0 && o[2] === 113) return 'doc';
    return 'public';
  }

  /* Addresses that stand outside the organisation's network. */
  function isExternal(ipClass) {
    return ipClass === 'public' || ipClass === 'doc' || ipClass === 'ipv6';
  }

  function lookup(ip) {
    var found = [];
    for (var i = 0; i < LISTS.length; i++) {
      if (LISTS[i].ips.indexOf(ip) !== -1) {
        found.push({ id: LISTS[i].id, name: LISTS[i].name, updated: LISTS[i].updated });
      }
    }
    return found;
  }

  var api = { classifyIp: classifyIp, isExternal: isExternal, lookup: lookup, listCount: LISTS.length };
  AF.intel = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
