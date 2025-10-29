function hexToStr(h) {
  if (!h) return "";
  let s = "";
  for (let i = 0; i < h.length; i += 2) {
    s += String.fromCharCode(parseInt(h.substr(i, 2), 16));
  }
  return s;
}

function toB64(t) {
  try {
    return btoa(unescape(encodeURIComponent(t)));
  } catch (e) {
    if (typeof Buffer !== "undefined")
      return Buffer.from(t, "utf8").toString("base64");
    throw e;
  }
}

function parseAddressLine(line) {
  if (!line) return null;
  let t = String(line).trim();
  if (!t) return null;
  let host = "";
  let port = "443";
  let remark = t;

  if (t.includes("#")) {
    const parts = t.split("#");
    t = parts[0].trim();
    remark = parts.slice(1).join("#").trim() || t;
  }

  const ipv6PortMatch = t.match(/^\[([0-9a-fA-F:]+)\](?::(\d+))?$/);
  if (ipv6PortMatch) {
    host = ipv6PortMatch[1];
    if (ipv6PortMatch[2]) port = ipv6PortMatch[2];
  } else if (t.includes(":")) {
    const lastColon = t.lastIndexOf(":");
    const maybePort = t.substring(lastColon + 1);
    if (/^\d+$/.test(maybePort)) {
      host = t.substring(0, lastColon);
      port = maybePort;
      if (host.includes(":")) host = `[${host}]`;
    } else {
      host = t;
    }
  } else {
    host = t;
  }

  host = host.trim();
  port = port.trim();
  if (!host) return null;
  return { host, port, remark };
}

function buildVless(uuid, host, port, params, remark) {
  const q = new URLSearchParams();
  q.set("encryption", params.encryption || "none");
  if (params.security) q.set("security", params.security);
  if (params.sni) q.set("sni", params.sni);
  if (params.alpn) q.set("alpn", params.alpn);
  if (params.fp) q.set("fp", params.fp);
  if (params.allowInsecure) q.set("allowInsecure", params.allowInsecure);
  if (params.mode) q.set("mode", params.mode);
  q.set("type", params.type || "xhttp");
  if (params.host) q.set("host", params.host);
  if (params.path) q.set("path", params.path);
  const hostStr = host.includes(":") ? `[${host}]` : host;
  return `vless://${uuid}@${hostStr}:${port}?${q.toString()}#${encodeURIComponent(remark)}`;
}

async function fetchLinesSafe(url) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": "WorkerVless2sub" } });
    if (!r.ok) return [];
    const txt = await r.text();
    return txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

const H_DOM = [
  "icoook.tw:2053",
  "cloudflare.cfgo.cc",
  "www.visa.com.sg:2053",
  "www.wto.org:2053",
  "www.who.int:2053",
  "skk.moe",
  "icoook.hk",
  "icoook.tw",
  "cf.090227.xyz",
  "acsg3.cloudflarest.link",
  "acus.cloudflarest.link",
  "wz.weishao2023.dk.eu.org",
  "achk.cloudflarest.link",
];

const H_API = [
  "https://raw.githubusercontent.com/cmliu/Workervless2sub/main/addressesapi.txt?proxyip=true",
  "https://addressesapi.090227.xyz/cmcc",
  "https://addressesapi.090227.xyz/ct",
  "https://addressesapi.090227.xyz/cmcc-ipv6",
  "https://addressesapi.090227.xyz/CloudFlareYes",
  "https://addressesapi.090227.xyz/ip.164746.xyz",
  "https://www.surper7857.xyz/surper",
];

export default {
  async fetch(req) {
    try {
      const url = new URL(req.url);
      const uuid = url.searchParams.get("uuid") || "00000000-0000-0000-0000-000000000000";
      const params = {
        type: (url.searchParams.get("type") || "xhttp").toLowerCase(),
        encryption: url.searchParams.get("encryption") || "none",
        password: url.searchParams.get("password") || "",
        security: url.searchParams.get("security") || "",
        sni: url.searchParams.get("sni") || "",
        host: url.searchParams.get("host") || "",
        path: url.searchParams.get("path") || "/ray",
        allowInsecure: url.searchParams.get("allowInsecure") || "",
        alpn: url.searchParams.get("alpn") || "",
        fp: url.searchParams.get("fp") || "",
        mode: url.searchParams.get("mode") || ""
      };

      const set = new Set(H_DOM);
      for (const api of H_API) {
        const lines = await fetchLinesSafe(api);
        for (const l of lines) if (l) set.add(l);
      }

      const links = [];
      for (const it of set) {
        const p = parseAddressLine(it);
        if (!p) continue;
        links.push(buildVless(uuid, p.host, p.port, params, p.remark));
      }

      const out = links.join("\n");
      return new Response(toB64(out), {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Profile-Update-Interval": "6"
        }
      });
    } catch {
      return new Response(toB64(""), { headers: { "Content-Type": "text/plain" } });
    }
  }
};
