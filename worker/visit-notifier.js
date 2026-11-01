// Cloudflare Worker: receives a visit ping from the site and sends a short
// summary to Telegram. The visitor's IP address is never stored.
//
// Secrets (Worker → Settings → Variables and Secrets):
//   TELEGRAM_TOKEN    bot token from @BotFather
//   TELEGRAM_CHAT_ID  chat id that receives the notifications
//   HASH_SALT         any long random string (used for the daily visitor code)

const ALLOWED_ORIGIN = 'https://ilcons22.github.io';

// Crawlers, link previews and automated clients.
const BOT_UA = /bot|crawl|spider|slurp|preview|scan|monitor|headless|lighthouse|phantom|python|curl|wget|java\/|go-http|axios|node-fetch|facebookexternalhit|whatsapp|telegram|discord|slack|skype|embedly|pinterest|vkshare|w3c_validator/i;

export default {
    async fetch(request, env, ctx) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: cors() });
        }
        if (request.method !== 'POST') {
            return new Response('ok', { headers: cors() });
        }
        if (request.headers.get('Origin') !== ALLOWED_ORIGIN) {
            return new Response(null, { status: 403 });
        }

        const ua = request.headers.get('User-Agent') || '';
        if (!ua || BOT_UA.test(ua)) {
            return new Response(null, { status: 204, headers: cors() });
        }

        let body = {};
        try {
            body = JSON.parse(await request.text());
        } catch (e) {}

        ctx.waitUntil(notify(request, env, ua, body));
        return new Response(null, { status: 204, headers: cors() });
    },
};

async function notify(request, env, ua, body) {
    const cf = request.cf || {};
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const place = [cf.city, cf.region].filter(Boolean).join(', ') || 'Posizione sconosciuta';
    const country = cf.country ? ` ${flag(cf.country)} ${cf.country}` : '';
    const code = await visitorCode(ip, ua, env.HASH_SALT || '');

    const text = [
        '🔔 <b>Nuova visita</b>',
        `📍 ${escapeHtml(place)}${country}`,
        `🏢 ${escapeHtml(cf.asOrganization || 'Rete sconosciuta')}`,
        `💻 ${escapeHtml(describeUA(ua))}`,
        `↩️ ${escapeHtml(describeReferrer(body.ref))}`,
        `🆔 Visitatore #${code}`,
    ].join('\n');

    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            chat_id: env.TELEGRAM_CHAT_ID,
            text,
            parse_mode: 'HTML',
            disable_web_page_preview: true,
        }),
    });
    if (!res.ok) console.log('Telegram error', res.status, await res.text());
}

// Same visitor (IP + browser) on the same day → same code. Not reversible.
async function visitorCode(ip, ua, salt) {
    const day = new Date().toISOString().slice(0, 10);
    const data = new TextEncoder().encode(`${salt}|${day}|${ip}|${ua}`);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += alphabet[hash[i] % alphabet.length];
    return code;
}

function describeUA(ua) {
    const browser =
        /Edg(e|A|iOS)?\//.test(ua) ? 'Edge' :
        /OPR\/|Opera/.test(ua) ? 'Opera' :
        /SamsungBrowser/.test(ua) ? 'Samsung Internet' :
        /Firefox\/|FxiOS/.test(ua) ? 'Firefox' :
        /Chrome\/|CriOS/.test(ua) ? 'Chrome' :
        /Safari\//.test(ua) ? 'Safari' : 'Browser sconosciuto';
    const os =
        /iPhone|iPod/.test(ua) ? 'iPhone' :
        /iPad/.test(ua) ? 'iPad' :
        /Android/.test(ua) ? 'Android' :
        /Windows/.test(ua) ? 'Windows' :
        /Macintosh|Mac OS X/.test(ua) ? 'macOS' :
        /CrOS/.test(ua) ? 'ChromeOS' :
        /Linux/.test(ua) ? 'Linux' : 'sistema sconosciuto';
    return `${browser} su ${os}`;
}

function describeReferrer(ref) {
    if (!ref) return 'Accesso diretto';
    try {
        const host = new URL(ref).hostname.replace(/^www\./, '');
        return host === new URL(ALLOWED_ORIGIN).hostname ? 'Navigazione interna' : `Da ${host}`;
    } catch (e) {
        return 'Accesso diretto';
    }
}

function flag(cc) {
    if (!/^[A-Z]{2}$/.test(cc)) return '';
    return String.fromCodePoint(...[...cc].map(c => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function cors() {
    return {
        'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Headers': 'Content-Type',
    };
}
