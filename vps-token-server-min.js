// vps-token-server-min.js
//
// Minimal token-server actually deployed at /var/www/safetix/token-server.js
// on the production VPS. This is the source-of-truth for the VPS file —
// edit here, push, then deploy via:
//
//   sudo curl -fsSL https://raw.githubusercontent.com/premium-code/wallet-pass/main/vps-token-server-min.js -o /var/www/safetix/token-server.js
//   pm2 restart safetix
//
// Diverged from the 88KB token-server.js at repo root which has TM
// mobile-extract / dashboard / auth-session features that were never
// deployed. Keep this file thin — only what the VPS actually needs.
//
// Endpoints:
//   GET  /health
//   GET  /api/shorten              — list all (no auth, matches existing behavior)
//   GET  /api/shorten/:id          — public ticket-view (used by the secured-ticket-access viewer)
//   POST /api/shorten              — create a new short link (no auth, matches existing behavior)
//   PUT  /api/shorten/:id          — override existing link (auth required)
//   POST /api/shorten/lookup-signatures — bulk lookup seat-signatures → shortId map (auth required)
//   GET  /api/tickets/:order/:ticket — legacy ticket-database lookup
//
// Stored fields per short link:
//   tickets[], seatSignatures[], createdAt, updatedAt?, accessCount

const http = require('http'), fs = require('fs'), url = require('url');
const DATA_DIR = '/var/www/safetix/data';
const SHORT_LINKS_FILE = DATA_DIR + '/short-links.json';
const TICKET_DB_FILE = DATA_DIR + '/ticket-database.json';
const API_KEY = process.env.API_KEY || 'admin123';
let shortLinks = {}, ticketDB = {};

function loadShortLinks() { try { if (fs.existsSync(SHORT_LINKS_FILE)) shortLinks = JSON.parse(fs.readFileSync(SHORT_LINKS_FILE, 'utf8')); } catch(e) {} console.log('Loaded ' + Object.keys(shortLinks).length + ' links'); }
function loadTicketDB() { try { if (fs.existsSync(TICKET_DB_FILE)) ticketDB = JSON.parse(fs.readFileSync(TICKET_DB_FILE, 'utf8')); } catch(e) {} console.log('Loaded ' + Object.keys(ticketDB).length + ' orders in ticket database'); }
function saveShortLinks() { try { fs.writeFileSync(SHORT_LINKS_FILE, JSON.stringify(shortLinks, null, 2)); } catch(e) {} }
function generateShortId() { return Math.random().toString(36).substr(2, 8) + '-' + Math.random().toString(36).substr(2, 4) + '-' + Math.random().toString(36).substr(2, 4) + '-' + Math.random().toString(36).substr(2, 4) + '-' + Math.random().toString(36).substr(2, 12) + Math.floor(Math.random()*100); }
function parseBody(req) { return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => { try { r(JSON.parse(b)); } catch(e) { r({}); } }); }); }
function isAuthed(req) { return req.headers['x-api-key'] === API_KEY; }

const server = http.createServer(async (req, res) => {
    const headers = {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': '*'};
    if (req.method === 'OPTIONS') { res.writeHead(204, headers); res.end(); return; }
    const u = url.parse(req.url, true), p = u.pathname;
    try {
        if (p === '/health') { res.writeHead(200, headers); res.end(JSON.stringify({status: 'ok'})); return; }

        // POST /api/shorten/lookup-signatures - bulk seat-signature lookup.
        // Must come before the generic /api/shorten/:id handlers below so the
        // path doesn't get parsed as a shortId.
        if (p === '/api/shorten/lookup-signatures' && req.method === 'POST') {
            if (!isAuthed(req)) { res.writeHead(401, headers); res.end(JSON.stringify({success: false, error: 'Authentication required'})); return; }
            const body = await parseBody(req);
            if (!Array.isArray(body.signatures)) { res.writeHead(400, headers); res.end(JSON.stringify({success: false, error: 'Expected { signatures: [...] }'})); return; }
            // Reverse-index: most recent shortId per signature wins.
            const records = Object.entries(shortLinks).map(([id, d]) => ({id, createdAt: d.createdAt || '', sigs: Array.isArray(d.seatSignatures) ? d.seatSignatures : []}));
            records.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
            const index = {};
            for (const r of records) for (const s of r.sigs) if (typeof s === 'string' && s) index[s] = r.id;
            const results = {};
            for (const s of body.signatures) results[s] = index[s] || null;
            res.writeHead(200, headers); res.end(JSON.stringify({success: true, results})); return;
        }

        // PUT /api/shorten/:id - replace tickets + seatSignatures, preserve createdAt/accessCount.
        if (p.startsWith('/api/shorten/') && req.method === 'PUT') {
            if (!isAuthed(req)) { res.writeHead(401, headers); res.end(JSON.stringify({success: false, error: 'Authentication required'})); return; }
            const id = p.split('/')[3];
            const body = await parseBody(req);
            if (!body.tickets || !body.tickets.length) { res.writeHead(400, headers); res.end(JSON.stringify({success: false, error: 'No tickets'})); return; }
            if (!shortLinks[id]) { res.writeHead(404, headers); res.end(JSON.stringify({success: false, error: 'Not found'})); return; }
            const existing = shortLinks[id];
            shortLinks[id] = {
                tickets: body.tickets,
                seatSignatures: Array.isArray(body.seatSignatures) ? body.seatSignatures : (existing.seatSignatures || []),
                createdAt: existing.createdAt,
                updatedAt: new Date().toISOString(),
                accessCount: existing.accessCount || 0
            };
            saveShortLinks(); console.log('Overrode:', id);
            res.writeHead(200, headers); res.end(JSON.stringify({success: true, shortId: id, shortUrl: 'https://secured-ticket-access.com/index.html?t=' + id, ticketCount: body.tickets.length, createdAt: shortLinks[id].createdAt, updatedAt: shortLinks[id].updatedAt})); return;
        }

        if (p.startsWith('/api/shorten/') && req.method === 'GET') {
            const id = p.split('/')[3];
            if (shortLinks[id]) { shortLinks[id].accessCount = (shortLinks[id].accessCount || 0) + 1; saveShortLinks(); res.writeHead(200, headers); res.end(JSON.stringify({success: true, tickets: shortLinks[id].tickets})); return; }
            res.writeHead(404, headers); res.end(JSON.stringify({success: false, error: 'Not found'})); return;
        }

        if (p === '/api/shorten' && req.method === 'GET') {
            const links = Object.entries(shortLinks).map(([id, d]) => ({id, shortUrl: 'https://secured-ticket-access.com/index.html?t=' + id, ticketCount: d.tickets?.length || 0, eventName: d.tickets?.[0]?.eventName || d.tickets?.[0]?.event || '', eventDate: d.tickets?.[0]?.date || '', accessCount: d.accessCount || 0}));
            res.writeHead(200, headers); res.end(JSON.stringify({success: true, count: links.length, links})); return;
        }

        if (p === '/api/shorten' && req.method === 'POST') {
            const body = await parseBody(req);
            if (!body.tickets?.length) { res.writeHead(400, headers); res.end(JSON.stringify({error: 'No tickets'})); return; }
            const id = generateShortId();
            shortLinks[id] = {
                tickets: body.tickets,
                seatSignatures: Array.isArray(body.seatSignatures) ? body.seatSignatures : [],
                createdAt: new Date().toISOString(),
                accessCount: 0
            };
            saveShortLinks(); console.log('Created:', id);
            res.writeHead(200, headers); res.end(JSON.stringify({success: true, shortId: id, shortUrl: 'https://secured-ticket-access.com/index.html?t=' + id})); return;
        }

        if (p.startsWith('/api/tickets/') && req.method === 'GET') {
            const parts = p.split('/');
            const orderId = parts[3], ticketId = parts[4];
            if (ticketDB[orderId]) {
                const orderTickets = ticketDB[orderId];
                if (ticketId) {
                    const ticket = orderTickets.find(t => t.id === ticketId);
                    if (ticket) { res.writeHead(200, headers); res.end(JSON.stringify({success: true, tickets: [ticket]})); return; }
                } else {
                    res.writeHead(200, headers); res.end(JSON.stringify({success: true, tickets: orderTickets})); return;
                }
            }
            res.writeHead(404, headers); res.end(JSON.stringify({success: false, error: 'Order not found'})); return;
        }

        res.writeHead(404, headers); res.end(JSON.stringify({error: 'Not found'}));
    } catch(e) { console.error(e); res.writeHead(500, headers); res.end(JSON.stringify({error: 'Server error'})); }
});

loadShortLinks();
loadTicketDB();
server.listen(3847, '0.0.0.0', () => console.log('Server running on port 3847'));
