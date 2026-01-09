/**
 * Local Token Server
 * Receives and manages SafeTix tokens from both:
 * - Chrome extension (web capture)
 * - mitmproxy (mobile app capture)
 *
 * Run: node token-server.js
 * Default port: 3847
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const TMMobileAPI = require('./tm-mobile-api');

// Configuration
const PORT = process.env.PORT || 3847;
const DATA_DIR = path.join(__dirname, 'data');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const BARCODELESS_FILE = path.join(DATA_DIR, 'barcodeless-links.json');
const ALERTS_FILE = path.join(DATA_DIR, 'alert-config.json');
const SHORT_LINKS_FILE = path.join(DATA_DIR, 'short-links.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const TICKET_DB_FILE = path.join(DATA_DIR, 'ticket-database.json');

// Admin authentication - CHANGE THIS PASSWORD!
let authConfig = {
    password: 'admin123',  // Default password - change this!
    sessionToken: null,
    sessionExpiry: null
};

// Load auth config
function loadAuthConfig() {
    try {
        if (fs.existsSync(AUTH_FILE)) {
            authConfig = { ...authConfig, ...JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')) };
        }
    } catch (e) {
        console.error('Error loading auth config:', e.message);
    }
}

// Save auth config
function saveAuthConfig() {
    try {
        fs.writeFileSync(AUTH_FILE, JSON.stringify({ password: authConfig.password }, null, 2));
    } catch (e) {
        console.error('Error saving auth config:', e.message);
    }
}

// Generate session token
function generateSessionToken() {
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// Check if request is authenticated
function isAuthenticated(req) {
    // Check for API key in header (for extension/API access)
    const apiKey = req.headers['x-api-key'];
    if (apiKey && apiKey === authConfig.password) {
        return true;
    }

    // Check for session token in cookie or header (for browser access)
    const cookies = parseCookies(req);
    const headerToken = req.headers['x-auth-token'];
    const token = cookies['sta_session'] || headerToken;

    if (token && token === authConfig.sessionToken) {
        // Check if session is still valid (24 hours)
        if (authConfig.sessionExpiry && new Date(authConfig.sessionExpiry) > new Date()) {
            return true;
        }
    }
    return false;
}

// Parse cookies from request
function parseCookies(req) {
    const cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            cookies[name] = value;
        });
    }
    return cookies;
}

// Protected endpoints that require authentication
const PROTECTED_ENDPOINTS = [
    '/dashboard',
    '/api/tokens',
    '/api/links',
    '/api/config',
    '/api/barcodeless',
    '/api/alerts',
    '/api/shorten',  // List all short links (GET without ID)
    '/api/stats',
    '/api/auth-session',
    '/api/mobile',
    '/api/device',
    '/api/wallet'
];

// Check if endpoint requires auth
function requiresAuth(pathname) {
    // Public endpoints (no auth needed):
    // - /health
    // - /api/shorten/:id (GET specific short link for public ticket viewing)
    // - /login, /api/login
    // - OPTIONS (CORS preflight)

    // Allow public access to individual short links
    if (pathname.match(/^\/api\/shorten\/[a-zA-Z0-9-]+$/)) {
        return false;
    }

    // Allow public access to ticket database lookups (for old CSV links)
    if (pathname.match(/^\/api\/tickets\/[a-zA-Z0-9-]+/)) {
        return false;
    }

    // Check if it's a protected endpoint
    return PROTECTED_ENDPOINTS.some(ep => pathname.startsWith(ep));
}

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory token store
let tokens = {};
let config = {
    baseUrl: 'https://secured-ticket-access.com',
    autoGenerateLinks: true
};

// Barcodeless links storage
let barcodelessLinks = {};
let alertConfig = {
    email: '',
    enabled: false,
    hoursBeforeEvent: 48,
    lastChecked: null,
    sentAlerts: {} // Track which alerts have been sent
};

// Short links storage - maps short ID to full ticket data
let shortLinks = {};

// Ticket database - maps order ID to array of tickets (for old ?ord=&id= links)
let ticketDB = {};

// Load existing data
function loadData() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            tokens = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
            console.log(`Loaded ${Object.keys(tokens).length} existing tokens`);
        }
        if (fs.existsSync(CONFIG_FILE)) {
            config = { ...config, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
        }
        if (fs.existsSync(BARCODELESS_FILE)) {
            barcodelessLinks = JSON.parse(fs.readFileSync(BARCODELESS_FILE, 'utf8'));
            console.log(`Loaded ${Object.keys(barcodelessLinks).length} barcodeless links`);
        }
        if (fs.existsSync(ALERTS_FILE)) {
            alertConfig = { ...alertConfig, ...JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8')) };
            if (alertConfig.email) {
                console.log(`Alert email configured: ${alertConfig.email}`);
            }
        }
        if (fs.existsSync(SHORT_LINKS_FILE)) {
            shortLinks = JSON.parse(fs.readFileSync(SHORT_LINKS_FILE, 'utf8'));
            console.log(`Loaded ${Object.keys(shortLinks).length} short links`);
        }
        if (fs.existsSync(TICKET_DB_FILE)) {
            ticketDB = JSON.parse(fs.readFileSync(TICKET_DB_FILE, 'utf8'));
            console.log(`Loaded ${Object.keys(ticketDB).length} orders in ticket database`);
        }
    } catch (e) {
        console.error('Error loading data:', e.message);
    }
}

// Save short links
function saveShortLinks() {
    try {
        fs.writeFileSync(SHORT_LINKS_FILE, JSON.stringify(shortLinks, null, 2));
    } catch (e) {
        console.error('Error saving short links:', e.message);
    }
}

// Generate short ID (UUID-style with suffix, like 960a3a85-e638-47a9-9936-ac9c3fd8250c6)
function generateShortId() {
    const hex = () => Math.random().toString(16).substring(2, 10);
    const suffix = Math.floor(Math.random() * 100); // 0-99 suffix
    const id = `${hex()}-${hex().substring(0,4)}-${hex().substring(0,4)}-${hex().substring(0,4)}-${hex()}${hex().substring(0,4)}${suffix}`;
    // Ensure uniqueness
    if (shortLinks[id]) {
        return generateShortId();
    }
    return id;
}

// Save barcodeless links
function saveBarcodelessLinks() {
    try {
        fs.writeFileSync(BARCODELESS_FILE, JSON.stringify(barcodelessLinks, null, 2));
    } catch (e) {
        console.error('Error saving barcodeless links:', e.message);
    }
}

// Save alert config
function saveAlertConfig() {
    try {
        fs.writeFileSync(ALERTS_FILE, JSON.stringify(alertConfig, null, 2));
    } catch (e) {
        console.error('Error saving alert config:', e.message);
    }
}

// Parse event date string to Date object
function parseEventDate(dateStr) {
    if (!dateStr) return null;
    try {
        // Handle various date formats
        // "Wed, Nov 25, 2026, 7:30 PM" or "November 25, 2026" etc.
        const cleaned = dateStr
            .replace(/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s*/i, '')
            .replace(/\s+/g, ' ')
            .trim();

        const parsed = new Date(cleaned);
        if (!isNaN(parsed.getTime())) {
            return parsed;
        }

        // Try another approach - extract date parts
        const match = dateStr.match(/(\w+)\s+(\d{1,2}),?\s+(\d{4})/);
        if (match) {
            const months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
            const monthIdx = months.findIndex(m => match[1].toLowerCase().startsWith(m));
            if (monthIdx >= 0) {
                return new Date(parseInt(match[3]), monthIdx, parseInt(match[2]));
            }
        }
    } catch (e) {
        console.error('Error parsing date:', dateStr, e.message);
    }
    return null;
}

// Check for upcoming events needing alerts
function checkUpcomingEvents() {
    if (!alertConfig.enabled || !alertConfig.email) return [];

    const now = new Date();
    const alertThreshold = alertConfig.hoursBeforeEvent || 48;
    const upcomingAlerts = [];

    for (const [id, link] of Object.entries(barcodelessLinks)) {
        const eventDate = parseEventDate(link.eventDate);
        if (!eventDate) continue;

        const hoursUntilEvent = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);

        // Check if within alert window and hasn't been alerted yet
        if (hoursUntilEvent > 0 && hoursUntilEvent <= alertThreshold) {
            const alertKey = `${id}_${alertThreshold}h`;
            if (!alertConfig.sentAlerts[alertKey]) {
                upcomingAlerts.push({
                    id,
                    ...link,
                    hoursUntilEvent: Math.round(hoursUntilEvent),
                    alertKey
                });
            }
        }
    }

    return upcomingAlerts;
}

// Simple email sending (logs to console - integrate with actual email service)
async function sendAlertEmail(alerts) {
    if (!alertConfig.email || alerts.length === 0) return;

    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║          BARCODELESS LINK ALERT                            ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Email: ${alertConfig.email.padEnd(46)}║`);
    console.log(`║  ${alerts.length} event(s) within ${alertConfig.hoursBeforeEvent} hours!`.padEnd(58) + '║');
    console.log('╠════════════════════════════════════════════════════════════╣');

    for (const alert of alerts) {
        console.log(`║  Event: ${(alert.eventName || 'Unknown').substring(0, 45).padEnd(45)}║`);
        console.log(`║  Date: ${(alert.eventDate || '').substring(0, 46).padEnd(46)}║`);
        console.log(`║  Venue: ${(alert.venue || '').substring(0, 45).padEnd(45)}║`);
        console.log(`║  Section ${alert.section || '?'} Row ${alert.row || '?'} Seat ${alert.seat || '?'}`.padEnd(58) + '║');
        console.log(`║  Link: ${(alert.link || '').substring(0, 46).padEnd(46)}║`);
        console.log('║                                                            ║');

        // Mark as sent
        alertConfig.sentAlerts[alert.alertKey] = new Date().toISOString();
    }

    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  ACTION: Barcodes may now be available!                    ║');
    console.log('║  Re-scan these tickets to get rotating barcodes.           ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');

    alertConfig.lastChecked = new Date().toISOString();
    saveAlertConfig();

    // TODO: Integrate with actual email service (nodemailer, SendGrid, etc.)
    // For now, just log to console
    return alerts.length;
}

// Save tokens to disk
function saveTokens() {
    try {
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
    } catch (e) {
        console.error('Error saving tokens:', e.message);
    }
}

// Generate shareable link for a token
function generateLink(token) {
    const params = new URLSearchParams({
        token: token.token,
        event: token.event_name || token.eventName || 'Event',
        date: token.date || '',
        sec: token.section || '',
        row: token.row || '',
        seat: token.seat || '',
        loc: token.venue || '',
        type: token.ticket_type || 'Standard Admission'
    });
    return `${config.baseUrl}/index.html?${params.toString()}`;
}

// CORS headers
function setCORSHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// Parse JSON body
async function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(e);
            }
        });
        req.on('error', reject);
    });
}

// Request handler
async function handleRequest(req, res) {
    setCORSHeaders(res);

    // Handle preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, `http://localhost:${PORT}`);
    const pathname = url.pathname;

    try {
        // ============================================
        // LOGIN / LOGOUT ENDPOINTS (Public)
        // ============================================

        // GET /login - Show login page
        if (pathname === '/login' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(getLoginPage());
            return;
        }

        // POST /api/login - Authenticate
        if (pathname === '/api/login' && req.method === 'POST') {
            const body = await parseBody(req);

            if (body.password === authConfig.password) {
                // Generate new session
                authConfig.sessionToken = generateSessionToken();
                authConfig.sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'Set-Cookie': `sta_session=${authConfig.sessionToken}; Path=/; HttpOnly; Max-Age=86400`
                });
                res.end(JSON.stringify({
                    success: true,
                    message: 'Logged in successfully',
                    token: authConfig.sessionToken
                }));
            } else {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Invalid password' }));
            }
            return;
        }

        // POST /api/logout - Logout
        if (pathname === '/api/logout' && req.method === 'POST') {
            authConfig.sessionToken = null;
            authConfig.sessionExpiry = null;

            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': 'sta_session=; Path=/; HttpOnly; Max-Age=0'
            });
            res.end(JSON.stringify({ success: true, message: 'Logged out' }));
            return;
        }

        // POST /api/change-password - Change password (requires auth)
        if (pathname === '/api/change-password' && req.method === 'POST') {
            if (!isAuthenticated(req)) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Not authenticated' }));
                return;
            }

            const body = await parseBody(req);
            if (body.newPassword && body.newPassword.length >= 6) {
                authConfig.password = body.newPassword;
                saveAuthConfig();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Password changed' }));
            } else {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Password must be at least 6 characters' }));
            }
            return;
        }

        // ============================================
        // AUTHENTICATION CHECK FOR PROTECTED ROUTES
        // ============================================

        if (requiresAuth(pathname) && !isAuthenticated(req)) {
            // For API requests, return 401
            if (pathname.startsWith('/api/')) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Authentication required' }));
                return;
            }
            // For dashboard/pages, redirect to login
            res.writeHead(302, { 'Location': '/login' });
            res.end();
            return;
        }

        // ============================================
        // API Routes (Protected)
        // ============================================

        // GET /api/tokens - List all tokens
        if (pathname === '/api/tokens' && req.method === 'GET') {
            const tokenList = Object.values(tokens).map(t => ({
                ...t,
                link: generateLink(t)
            }));

            // Optional filtering
            const source = url.searchParams.get('source');
            const event = url.searchParams.get('event');

            let filtered = tokenList;
            if (source) {
                filtered = filtered.filter(t => t.source === source);
            }
            if (event) {
                filtered = filtered.filter(t =>
                    (t.event_name || t.eventName || '').toLowerCase().includes(event.toLowerCase())
                );
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                count: filtered.length,
                tokens: filtered
            }));
            return;
        }

        // POST /api/tokens - Add new token(s)
        if (pathname === '/api/tokens' && req.method === 'POST') {
            const body = await parseBody(req);

            // Support single token or array
            const newTokens = Array.isArray(body) ? body : [body];
            let added = 0;
            let updated = 0;

            for (const token of newTokens) {
                const id = token.barcode_id || token.barcode || token.decoded?.b || `token_${Date.now()}`;

                if (tokens[id]) {
                    // Update existing
                    tokens[id] = { ...tokens[id], ...token, updated_at: new Date().toISOString() };
                    updated++;
                } else {
                    // Add new
                    tokens[id] = {
                        ...token,
                        id,
                        created_at: new Date().toISOString()
                    };
                    added++;
                }

                console.log(`[${token.source || 'unknown'}] Token captured: ${token.event_name || 'Unknown Event'} - Sec ${token.section || '?'} Row ${token.row || '?'} Seat ${token.seat || '?'}`);
            }

            saveTokens();

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                added,
                updated,
                total: Object.keys(tokens).length
            }));
            return;
        }

        // GET /api/tokens/:id - Get single token
        if (pathname.startsWith('/api/tokens/') && req.method === 'GET') {
            const id = pathname.split('/').pop();
            const token = tokens[id];

            if (token) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    token: { ...token, link: generateLink(token) }
                }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Token not found' }));
            }
            return;
        }

        // DELETE /api/tokens/:id - Delete token
        if (pathname.startsWith('/api/tokens/') && req.method === 'DELETE') {
            const id = pathname.split('/').pop();

            if (tokens[id]) {
                delete tokens[id];
                saveTokens();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Token not found' }));
            }
            return;
        }

        // POST /api/tokens/clear - Clear all tokens
        if (pathname === '/api/tokens/clear' && req.method === 'POST') {
            const count = Object.keys(tokens).length;
            tokens = {};
            saveTokens();

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, cleared: count }));
            return;
        }

        // GET /api/links - Generate links for all tokens
        if (pathname === '/api/links' && req.method === 'GET') {
            const links = Object.values(tokens).map(t => ({
                id: t.id || t.barcode_id,
                event: t.event_name || t.eventName,
                section: t.section,
                row: t.row,
                seat: t.seat,
                link: generateLink(t),
                source: t.source
            }));

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, links }));
            return;
        }

        // POST /api/links/generate - Generate link for specific tokens
        if (pathname === '/api/links/generate' && req.method === 'POST') {
            const body = await parseBody(req);
            const ids = body.ids || [];

            const links = ids
                .filter(id => tokens[id])
                .map(id => ({
                    id,
                    link: generateLink(tokens[id])
                }));

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, links }));
            return;
        }

        // GET /api/config - Get configuration
        if (pathname === '/api/config' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, config }));
            return;
        }

        // POST /api/config - Update configuration
        if (pathname === '/api/config' && req.method === 'POST') {
            const body = await parseBody(req);
            config = { ...config, ...body };
            fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, config }));
            return;
        }

        // ============================================
        // MOBILE API EXTRACTION ENDPOINTS
        // ============================================

        // POST /api/mobile/extract - Extract tokens using mobile API
        if (pathname === '/api/mobile/extract' && req.method === 'POST') {
            const body = await parseBody(req);
            const { cookies, orderToken, eventId, eventName, venue, date, tickets: ticketList } = body;

            // Check for any valid auth cookies (not just SOTC)
            const authCookies = ['SOTC', 'id-token', 'access_token', 'tmuo', 'TM_VISITOR_GUID'];
            const hasAuth = cookies && authCookies.some(name => cookies[name]);
            const cookieCount = cookies ? Object.keys(cookies).length : 0;

            if (!cookies || (!hasAuth && cookieCount < 5)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Missing auth cookies. Got: ' + Object.keys(cookies || {}).join(', ') }));
                return;
            }

            console.log('[Mobile Extract] Auth cookies:', authCookies.filter(n => cookies[n]).join(', ') || 'none (using ' + cookieCount + ' total)');

            console.log('[Mobile Extract] Starting extraction...');
            console.log('[Mobile Extract] Order Token:', orderToken);
            console.log('[Mobile Extract] Event ID:', eventId);
            console.log('[Mobile Extract] Event Name:', eventName);
            console.log('[Mobile Extract] Venue:', venue);
            console.log('[Mobile Extract] Tickets:', JSON.stringify(ticketList || []));

            try {
                const api = new TMMobileAPI(cookies);
                let extractedTokens = [];

                // First try the hybrid approach (web-based, no device binding needed)
                // Pass ticket list with barcodes for the secure-barcode endpoint
                console.log('[Mobile Extract] Trying hybrid extraction (web-first)...');
                const hybridTokens = await api.extractTokensHybrid(eventId, orderToken, ticketList || []);
                if (hybridTokens.length > 0) {
                    extractedTokens = hybridTokens.map(t => ({
                        ...t,
                        eventName: eventName || '',
                        venue: venue || '',
                        date: date || '',
                        source: 'web-api'
                    }));
                    console.log(`[Mobile Extract] Hybrid extraction successful! Got ${extractedTokens.length} tokens`);
                }

                // If we have specific tickets to extract
                if (ticketList && ticketList.length > 0) {
                    // Try to get secure tickets for each
                    for (const ticket of ticketList) {
                        const evtId = ticket.eventId || eventId;
                        const ordTok = ticket.orderToken || orderToken;

                        if (evtId && ordTok) {
                            console.log(`[Mobile Extract] Fetching tickets for event ${evtId}...`);
                            const response = await api.getSecureTickets(evtId, ordTok);

                            if (response.status === 200) {
                                const tokens = api.extractTokensFromResponse(response);
                                tokens.forEach(t => {
                                    extractedTokens.push({
                                        ...t,
                                        eventName: ticket.eventName || eventName || '',
                                        venue: ticket.venue || venue || '',
                                        date: ticket.date || date || '',
                                        source: 'mobile-api'
                                    });
                                });
                            } else {
                                console.log(`[Mobile Extract] Failed for event ${evtId}:`, response.status, response.data);
                            }
                        }
                    }
                } else if (eventId && orderToken) {
                    // Single event extraction
                    const response = await api.getSecureTickets(eventId, orderToken);

                    if (response.status === 200) {
                        extractedTokens = api.extractTokensFromResponse(response).map(t => ({
                            ...t,
                            eventName: eventName || '',
                            venue: venue || '',
                            date: date || '',
                            source: 'mobile-api'
                        }));
                    }
                } else if (orderToken) {
                    // We have orderToken but no eventId - get order info first
                    console.log('[Mobile Extract] Have orderToken but no eventId, fetching order info...');
                    const orderResponse = await api.getOrderInfo(orderToken);
                    console.log('[Mobile Extract] Order info response:', orderResponse.status);

                    if (orderResponse.status === 200 && orderResponse.data) {
                        const orderData = orderResponse.data;
                        console.log('[Mobile Extract] Order data:', JSON.stringify(orderData, null, 2).substring(0, 1500));

                        // Extract event ID from order
                        const evtId = orderData.eventId || orderData.event?.id || orderData.events?.[0]?.id;
                        const evtName = eventName || orderData.eventName || orderData.event?.name || '';
                        const evtVenue = venue || orderData.venue?.name || orderData.event?.venue?.name || '';
                        const evtDate = date || orderData.eventDate || orderData.event?.date || '';

                        if (evtId) {
                            console.log(`[Mobile Extract] Found eventId: ${evtId}, fetching secure tickets...`);
                            const response = await api.getSecureTickets(evtId, orderToken);

                            if (response.status === 200) {
                                extractedTokens = api.extractTokensFromResponse(response).map(t => ({
                                    ...t,
                                    eventName: evtName,
                                    venue: evtVenue,
                                    date: evtDate,
                                    source: 'mobile-api'
                                }));
                            }
                        } else {
                            // Try to get tickets directly from order data
                            const tickets = orderData.tickets || orderData.items || orderData.entryMedia || [];
                            for (const ticket of tickets) {
                                if (ticket.token || ticket.secureEntry?.token) {
                                    extractedTokens.push({
                                        token: ticket.token || ticket.secureEntry?.token,
                                        barcode: ticket.barcode || ticket.barcodeValue,
                                        section: ticket.section || ticket.sectionName,
                                        row: ticket.row || ticket.rowName,
                                        seat: ticket.seat || ticket.seatNumber,
                                        eventName: evtName,
                                        venue: evtVenue,
                                        date: evtDate,
                                        source: 'mobile-api'
                                    });
                                }
                            }
                        }
                    }
                } else {
                    // No specific event - fetch all events and extract tokens from each
                    console.log('[Mobile Extract] No specific event, fetching all events...');
                    const eventsResponse = await api.getMyEvents();

                    if (eventsResponse.status === 200 && eventsResponse.data) {
                        const events = eventsResponse.data.events || eventsResponse.data.items || eventsResponse.data || [];
                        console.log(`[Mobile Extract] Found ${Array.isArray(events) ? events.length : 0} events`);

                        // Process each event
                        const eventsList = Array.isArray(events) ? events : [];
                        for (const event of eventsList) {
                            const evtId = event.id || event.eventId;
                            const evtName = event.name || event.eventName || '';
                            const evtVenue = event.venue?.name || event.venueName || '';
                            const evtDate = event.date || event.eventDate || event.startDate || '';

                            // Get orders for this event
                            const orders = event.orders || event.tickets || [event];
                            for (const order of orders) {
                                const ordTok = order.orderToken || order.token || order.id;

                                if (evtId && ordTok) {
                                    console.log(`[Mobile Extract] Fetching tickets for event: ${evtName} (${evtId})`);
                                    try {
                                        const ticketResponse = await api.getSecureTickets(evtId, ordTok);

                                        if (ticketResponse.status === 200) {
                                            const tokens = api.extractTokensFromResponse(ticketResponse);
                                            tokens.forEach(t => {
                                                extractedTokens.push({
                                                    ...t,
                                                    eventName: evtName,
                                                    venue: evtVenue,
                                                    date: evtDate,
                                                    source: 'mobile-api'
                                                });
                                            });
                                            console.log(`[Mobile Extract] Got ${tokens.length} tokens for ${evtName}`);
                                        }
                                    } catch (err) {
                                        console.log(`[Mobile Extract] Error fetching ${evtName}:`, err.message);
                                    }
                                }
                            }
                        }
                    } else {
                        console.log('[Mobile Extract] Failed to fetch events:', eventsResponse.status);
                    }
                }

                // Save extracted tokens
                let added = 0;
                for (const token of extractedTokens) {
                    const id = token.barcode || `mobile_${Date.now()}_${added}`;
                    if (!tokens[id]) {
                        tokens[id] = {
                            ...token,
                            id,
                            created_at: new Date().toISOString()
                        };
                        added++;
                        console.log(`[Mobile Extract] Captured: Sec ${token.section || '?'} Row ${token.row || '?'} Seat ${token.seat || '?'}`);
                    }
                }

                if (added > 0) {
                    saveTokens();
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    extracted: extractedTokens.length,
                    added: added,
                    tokens: extractedTokens
                }));

            } catch (e) {
                console.error('[Mobile Extract] Error:', e.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // POST /api/mobile/orders - Get user's orders via mobile API
        if (pathname === '/api/mobile/orders' && req.method === 'POST') {
            const body = await parseBody(req);
            const { cookies } = body;

            if (!cookies || !cookies.SOTC) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Missing SOTC cookie' }));
                return;
            }

            try {
                const api = new TMMobileAPI(cookies);
                const response = await api.getMyEvents();

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: response.status === 200,
                    status: response.status,
                    data: response.data
                }));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // ============================================
        // AUTH SESSION CAPTURE (SMP-style device binding)
        // ============================================

        // POST /api/auth-session - Receive auth data captured from web session
        if (pathname === '/api/auth-session' && req.method === 'POST') {
            const body = await parseBody(req);
            const { authData, url, timestamp } = body;

            console.log('');
            console.log('╔════════════════════════════════════════════════════════════╗');
            console.log('║          AUTH SESSION DATA CAPTURED                        ║');
            console.log('╠════════════════════════════════════════════════════════════╣');
            console.log('║  Source URL:', (url || 'unknown').substring(0, 50));
            console.log('║  Timestamp:', new Date(timestamp).toISOString());
            console.log('╠════════════════════════════════════════════════════════════╣');

            if (authData) {
                // Log captured cookies
                const cookieNames = Object.keys(authData.cookies || {});
                console.log('║  Cookies captured:', cookieNames.length);

                // Key TM auth cookies to look for
                const keyAuthCookies = [
                    'access_token', 'refresh_token', 'id_token',
                    'tmuo', 'eps_sid', 'SID', 'SSID', 'HSID',
                    'BIGipServer', 'TMUO', 'TM_SESSION', 'auth_token'
                ];

                const foundKeyCookies = keyAuthCookies.filter(name =>
                    cookieNames.some(c => c.toLowerCase().includes(name.toLowerCase()))
                );

                if (foundKeyCookies.length > 0) {
                    console.log('║  Key auth cookies found:', foundKeyCookies.join(', '));
                }

                // Log localStorage items
                const localStorageKeys = Object.keys(authData.localStorage || {});
                if (localStorageKeys.length > 0) {
                    console.log('║  LocalStorage items:', localStorageKeys.length);
                    localStorageKeys.forEach(key => {
                        console.log('║    -', key);
                    });
                }

                // Log sessionStorage items
                const sessionStorageKeys = Object.keys(authData.sessionStorage || {});
                if (sessionStorageKeys.length > 0) {
                    console.log('║  SessionStorage items:', sessionStorageKeys.length);
                }

                // Log any tokens found
                const tokenKeys = Object.keys(authData.tokens || {});
                if (tokenKeys.length > 0) {
                    console.log('║  Window tokens found:', tokenKeys.join(', '));
                }

                // Save auth session to file for analysis
                const authSessionFile = path.join(DATA_DIR, 'auth-session.json');
                const sessionData = {
                    capturedAt: new Date().toISOString(),
                    sourceUrl: url,
                    cookies: authData.cookies || {},
                    localStorage: authData.localStorage || {},
                    sessionStorage: authData.sessionStorage || {},
                    tokens: authData.tokens || {}
                };

                fs.writeFileSync(authSessionFile, JSON.stringify(sessionData, null, 2));
                console.log('║  Auth session saved to:', authSessionFile);

                // Check if we have enough to attempt mobile API auth
                const hasPotentialAuth = cookieNames.length > 0 ||
                    localStorageKeys.length > 0 ||
                    tokenKeys.length > 0;

                if (hasPotentialAuth) {
                    console.log('╠════════════════════════════════════════════════════════════╣');
                    console.log('║  Attempting to use captured session for mobile API...     ║');

                    // Try to use the captured auth for mobile API
                    try {
                        const api = new TMMobileAPI(authData.cookies || {});

                        // Test if we can access the mobile API
                        const testResponse = await api.getMyEvents();

                        if (testResponse.status === 200) {
                            console.log('║  SUCCESS! Mobile API accessible with web session        ║');
                            console.log('║  Events response:', JSON.stringify(testResponse.data).substring(0, 100));
                        } else {
                            console.log('║  Mobile API returned status:', testResponse.status);
                            console.log('║  This is expected - web cookies alone may not work      ║');
                            console.log('║  Need mobile device binding for full access             ║');
                        }
                    } catch (e) {
                        console.log('║  Mobile API test error:', e.message);
                    }
                }
            }

            console.log('╚════════════════════════════════════════════════════════════╝');
            console.log('');

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                message: 'Auth session captured',
                cookiesReceived: Object.keys(authData?.cookies || {}).length,
                localStorageReceived: Object.keys(authData?.localStorage || {}).length
            }));
            return;
        }

        // POST /api/device/setup - Attempt device binding with captured auth session
        if (pathname === '/api/device/setup' && req.method === 'POST') {
            const body = await parseBody(req);

            console.log('');
            console.log('╔════════════════════════════════════════════════════════════╗');
            console.log('║          ATTEMPTING DEVICE SETUP                           ║');
            console.log('╚════════════════════════════════════════════════════════════╝');

            // Load saved auth session if not provided
            let authData = body.authData;
            if (!authData) {
                const authSessionFile = path.join(DATA_DIR, 'auth-session.json');
                if (fs.existsSync(authSessionFile)) {
                    const sessionData = JSON.parse(fs.readFileSync(authSessionFile, 'utf8'));
                    authData = {
                        cookies: sessionData.cookies,
                        localStorage: sessionData.localStorage,
                        tokens: sessionData.tokens
                    };
                    console.log('[Device Setup] Using saved auth session');
                }
            }

            if (!authData || !authData.cookies) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'No auth session available. Visit TM page first.' }));
                return;
            }

            try {
                // Try to find access token from various sources
                let accessToken = authData.cookies.access_token ||
                                  authData.cookies.SOTC ||
                                  authData.localStorage?.access_token ||
                                  authData.tokens?.accessToken;

                console.log('[Device Setup] Access token found:', !!accessToken);

                // Initialize API with cookies
                const api = new TMMobileAPI(authData.cookies);

                // Attempt device setup
                const result = await api.setupDevice(accessToken);

                console.log('[Device Setup] Result:', JSON.stringify(result, null, 2));

                // If device setup succeeded, try to extract tokens
                if (result.bound || result.hasKey) {
                    console.log('[Device Setup] Attempting token extraction with bound device...');

                    // Try to extract tokens from any recent order
                    const { eventId, orderToken } = body;
                    if (eventId && orderToken) {
                        const ticketResult = await api.getSecureTicketsWithDevice(eventId, orderToken);
                        if (ticketResult.status === 200) {
                            const extractedTokens = api.extractTokensFromResponse(ticketResult);
                            result.tokens = extractedTokens;
                            console.log('[Device Setup] Extracted', extractedTokens.length, 'tokens!');
                        }
                    }
                }

                // Save device info for future use
                const deviceFile = path.join(DATA_DIR, 'device-binding.json');
                fs.writeFileSync(deviceFile, JSON.stringify({
                    ...result,
                    setupAt: new Date().toISOString()
                }, null, 2));

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, ...result }));

            } catch (e) {
                console.error('[Device Setup] Error:', e.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // POST /api/device/extract - Extract tokens using bound device
        if (pathname === '/api/device/extract' && req.method === 'POST') {
            const body = await parseBody(req);
            const { eventId, orderToken, barcodes } = body;

            console.log('');
            console.log('╔════════════════════════════════════════════════════════════╗');
            console.log('║          EXTRACTING TOKENS WITH BOUND DEVICE               ║');
            console.log('╠════════════════════════════════════════════════════════════╣');
            console.log('║  Event ID:', eventId || 'not provided');
            console.log('║  Order Token:', (orderToken || 'not provided').substring(0, 30) + '...');
            console.log('║  Barcodes:', JSON.stringify(barcodes || []));
            console.log('╚════════════════════════════════════════════════════════════╝');

            // Load saved auth session
            const authSessionFile = path.join(DATA_DIR, 'auth-session.json');
            if (!fs.existsSync(authSessionFile)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'No auth session. Visit TM page first.' }));
                return;
            }

            try {
                const sessionData = JSON.parse(fs.readFileSync(authSessionFile, 'utf8'));
                const api = new TMMobileAPI(sessionData.cookies);

                // Load saved device info if available
                const deviceFile = path.join(DATA_DIR, 'device-binding.json');
                if (fs.existsSync(deviceFile)) {
                    const deviceData = JSON.parse(fs.readFileSync(deviceFile, 'utf8'));
                    if (deviceData.deviceKeySignature) {
                        api.deviceKeySignature = deviceData.deviceKeySignature;
                    }
                    if (deviceData.deviceId) {
                        api.deviceId = deviceData.deviceId;
                    }
                }

                // Extract tokens
                const ticketList = (barcodes || []).map(b => ({
                    barcode: b.barcode || b,
                    eventId: b.eventId || eventId,
                    section: b.section,
                    row: b.row,
                    seat: b.seat
                }));

                const extractedTokens = await api.extractTokensHybrid(eventId, orderToken, ticketList);

                // Save extracted tokens
                let added = 0;
                for (const token of extractedTokens) {
                    const id = token.barcode || `device_${Date.now()}_${added}`;
                    if (!tokens[id]) {
                        tokens[id] = {
                            ...token,
                            id,
                            source: 'device-bound',
                            created_at: new Date().toISOString()
                        };
                        added++;
                    }
                }

                if (added > 0) {
                    saveTokens();
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    extracted: extractedTokens.length,
                    added: added,
                    tokens: extractedTokens
                }));

            } catch (e) {
                console.error('[Device Extract] Error:', e.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // GET /api/auth-session - Get the captured auth session
        if (pathname === '/api/auth-session' && req.method === 'GET') {
            const authSessionFile = path.join(DATA_DIR, 'auth-session.json');

            if (fs.existsSync(authSessionFile)) {
                const sessionData = JSON.parse(fs.readFileSync(authSessionFile, 'utf8'));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, session: sessionData }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'No auth session captured yet' }));
            }
            return;
        }

        // POST /api/wallet/export - Fast wallet export (like SecureMyPass)
        if (pathname === '/api/wallet/export' && req.method === 'POST') {
            const body = await parseBody(req);
            const { cookies, orderToken, orderTokenJWT, eventId, tickets: ticketList, eventName, venue, date } = body;

            console.log('');
            console.log('╔════════════════════════════════════════════════════════════╗');
            console.log('║          WALLET EXPORT (Fast Mode)                         ║');
            console.log('╠════════════════════════════════════════════════════════════╣');
            console.log('║  Order Token:', (orderToken || 'none').substring(0, 40) + '...');
            console.log('║  JWT Token:', orderTokenJWT ? 'YES (' + orderTokenJWT.substring(0, 30) + '...)' : 'NO');
            console.log('║  Event ID:', eventId || 'none');
            console.log('║  Event:', eventName || 'unknown');
            console.log('║  Tickets:', (ticketList || []).length);
            console.log('╚════════════════════════════════════════════════════════════╝');

            if (!cookies) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Missing cookies' }));
                return;
            }

            try {
                const api = new TMMobileAPI(cookies);
                const extractedTokens = [];

                // If we have specific tickets, export each
                if (ticketList && ticketList.length > 0) {
                    for (const ticket of ticketList) {
                        const evtId = ticket.eventId || eventId;
                        const ordTok = ticket.orderToken || orderToken;

                        if (evtId && ordTok) {
                            console.log(`[Wallet Export] Exporting ticket: Sec ${ticket.section} Row ${ticket.row} Seat ${ticket.seat}`);
                            const result = await api.exportWalletPass(ordTok, evtId, ticket, orderTokenJWT);

                            if (result.success && result.tokens) {
                                result.tokens.forEach(t => {
                                    extractedTokens.push({
                                        ...t,
                                        eventName: ticket.eventName || eventName || '',
                                        venue: ticket.venue || venue || '',
                                        date: ticket.date || date || '',
                                        source: 'wallet-export'
                                    });
                                });
                            }
                        }
                    }
                } else if (eventId && orderToken) {
                    // Single export
                    const result = await api.exportWalletPass(orderToken, eventId, {}, orderTokenJWT);

                    if (result.success && result.tokens) {
                        result.tokens.forEach(t => {
                            extractedTokens.push({
                                ...t,
                                eventName: eventName || '',
                                venue: venue || '',
                                date: date || '',
                                source: 'wallet-export'
                            });
                        });
                    }
                }

                // Save extracted tokens
                let added = 0;
                for (const token of extractedTokens) {
                    const id = token.barcode || token.decoded?.b || `wallet_${Date.now()}_${added}`;
                    if (!tokens[id]) {
                        tokens[id] = {
                            ...token,
                            id,
                            created_at: new Date().toISOString()
                        };
                        added++;
                        console.log(`[Wallet Export] Saved: Sec ${token.section || '?'} Row ${token.row || '?'} Seat ${token.seat || '?'}`);
                    }
                }

                if (added > 0) {
                    saveTokens();
                }

                console.log(`[Wallet Export] Complete! Extracted ${extractedTokens.length}, Added ${added} new`);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: extractedTokens.length > 0,
                    extracted: extractedTokens.length,
                    added: added,
                    tokens: extractedTokens
                }));

            } catch (e) {
                console.error('[Wallet Export] Error:', e.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // POST /api/mobile/order-info - Get specific order info
        if (pathname === '/api/mobile/order-info' && req.method === 'POST') {
            const body = await parseBody(req);
            const { cookies, orderToken } = body;

            if (!cookies || !orderToken) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Missing cookies or orderToken' }));
                return;
            }

            try {
                const api = new TMMobileAPI(cookies);
                const response = await api.getOrderInfo(orderToken);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: response.status === 200,
                    status: response.status,
                    data: response.data
                }));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
            return;
        }

        // ============================================
        // BARCODELESS LINKS ENDPOINTS
        // ============================================

        // GET /api/barcodeless - List all barcodeless links
        if (pathname === '/api/barcodeless' && req.method === 'GET') {
            const linkList = Object.values(barcodelessLinks).map(link => {
                const eventDate = parseEventDate(link.eventDate);
                const now = new Date();
                let status = 'pending';
                let hoursUntilEvent = null;

                if (eventDate) {
                    hoursUntilEvent = Math.round((eventDate.getTime() - now.getTime()) / (1000 * 60 * 60));
                    if (hoursUntilEvent <= 0) {
                        status = 'past';
                    } else if (hoursUntilEvent <= 48) {
                        status = 'ready'; // Barcodes likely available
                    }
                }

                return {
                    ...link,
                    status,
                    hoursUntilEvent
                };
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                count: linkList.length,
                links: linkList
            }));
            return;
        }

        // POST /api/barcodeless - Save a barcodeless link
        if (pathname === '/api/barcodeless' && req.method === 'POST') {
            const body = await parseBody(req);
            const { link, eventName, eventDate, venue, section, row, seat } = body;

            if (!link) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Link is required' }));
                return;
            }

            const id = `bc_${Date.now()}_${section || ''}_${row || ''}_${seat || ''}`.replace(/\s+/g, '');

            barcodelessLinks[id] = {
                id,
                link,
                eventName: eventName || '',
                eventDate: eventDate || '',
                venue: venue || '',
                section: section || '',
                row: row || '',
                seat: seat || '',
                createdAt: new Date().toISOString(),
                hasBarcode: false
            };

            saveBarcodelessLinks();

            console.log(`[Barcodeless] Saved: ${eventName} - Sec ${section} Row ${row} Seat ${seat}`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                id,
                message: 'Barcodeless link saved. Will alert when barcodes become available.'
            }));
            return;
        }

        // DELETE /api/barcodeless/:id - Delete a barcodeless link
        if (pathname.startsWith('/api/barcodeless/') && req.method === 'DELETE') {
            const id = pathname.split('/').pop();

            if (barcodelessLinks[id]) {
                delete barcodelessLinks[id];
                saveBarcodelessLinks();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Link not found' }));
            }
            return;
        }

        // PUT /api/barcodeless/:id/barcode - Mark as having barcode now
        if (pathname.match(/\/api\/barcodeless\/[^/]+\/barcode$/) && req.method === 'PUT') {
            const parts = pathname.split('/');
            const id = parts[parts.length - 2];

            if (barcodelessLinks[id]) {
                barcodelessLinks[id].hasBarcode = true;
                barcodelessLinks[id].barcodeAddedAt = new Date().toISOString();
                saveBarcodelessLinks();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Marked as having barcode' }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Link not found' }));
            }
            return;
        }

        // ============================================
        // ALERT CONFIGURATION ENDPOINTS
        // ============================================

        // GET /api/alerts/config - Get alert configuration
        if (pathname === '/api/alerts/config' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                config: {
                    email: alertConfig.email,
                    enabled: alertConfig.enabled,
                    hoursBeforeEvent: alertConfig.hoursBeforeEvent,
                    lastChecked: alertConfig.lastChecked
                }
            }));
            return;
        }

        // POST /api/alerts/config - Update alert configuration
        if (pathname === '/api/alerts/config' && req.method === 'POST') {
            const body = await parseBody(req);

            if (body.email !== undefined) alertConfig.email = body.email;
            if (body.enabled !== undefined) alertConfig.enabled = body.enabled;
            if (body.hoursBeforeEvent !== undefined) alertConfig.hoursBeforeEvent = body.hoursBeforeEvent;

            saveAlertConfig();

            console.log(`[Alerts] Config updated: email=${alertConfig.email}, enabled=${alertConfig.enabled}`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, config: alertConfig }));
            return;
        }

        // GET /api/alerts/check - Manually check for upcoming events
        if (pathname === '/api/alerts/check' && req.method === 'GET') {
            const alerts = checkUpcomingEvents();

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                pending: alerts.length,
                alerts: alerts.map(a => ({
                    eventName: a.eventName,
                    eventDate: a.eventDate,
                    hoursUntilEvent: a.hoursUntilEvent,
                    section: a.section,
                    row: a.row,
                    seat: a.seat
                }))
            }));
            return;
        }

        // POST /api/alerts/send - Send pending alerts now
        if (pathname === '/api/alerts/send' && req.method === 'POST') {
            const alerts = checkUpcomingEvents();

            if (alerts.length > 0) {
                await sendAlertEmail(alerts);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, sent: alerts.length }));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, sent: 0, message: 'No pending alerts' }));
            }
            return;
        }

        // ============================================
        // SHORT LINK ENDPOINTS
        // ============================================

        // POST /api/shorten - Create a short link
        if (pathname === '/api/shorten' && req.method === 'POST') {
            const body = await parseBody(req);

            if (!body.tickets || !Array.isArray(body.tickets) || body.tickets.length === 0) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'No tickets provided' }));
                return;
            }

            const shortId = generateShortId();

            // Store ticket data with metadata
            shortLinks[shortId] = {
                id: shortId,
                tickets: body.tickets,
                createdAt: new Date().toISOString(),
                accessCount: 0,
                eventName: body.tickets[0]?.event || body.tickets[0]?.eventName || '',
                eventDate: body.tickets[0]?.date || ''
            };

            saveShortLinks();

            // Generate short URL - just the ID, no embedded data
            // Production page will fetch data via proxy -> ngrok -> this server
            const shortUrl = `${config.baseUrl}/index.html?t=${shortId}`;

            console.log(`[Short Link] Created: ${shortId} for ${body.tickets.length} ticket(s)`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                shortId: shortId,
                shortUrl: shortUrl,
                ticketCount: body.tickets.length
            }));
            return;
        }

        // GET /api/shorten/:id - Retrieve ticket data from short link
        if (pathname.startsWith('/api/shorten/') && req.method === 'GET') {
            const shortId = pathname.split('/')[3];

            if (shortLinks[shortId]) {
                // Increment access count
                shortLinks[shortId].accessCount++;
                shortLinks[shortId].lastAccessed = new Date().toISOString();
                saveShortLinks();

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    tickets: shortLinks[shortId].tickets,
                    createdAt: shortLinks[shortId].createdAt,
                    accessCount: shortLinks[shortId].accessCount
                }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Short link not found' }));
            }
            return;
        }

        // GET /api/shorten - List all short links
        if (pathname === '/api/shorten' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                count: Object.keys(shortLinks).length,
                links: Object.values(shortLinks).map(l => ({
                    id: l.id,
                    shortUrl: `${config.baseUrl}/index.html?t=${l.id}`,
                    ticketCount: l.tickets?.length || 0,
                    eventName: l.eventName,
                    eventDate: l.eventDate,
                    createdAt: l.createdAt,
                    accessCount: l.accessCount
                }))
            }));
            return;
        }

        // GET /api/export-links - Export raw short links data for backup/sync
        if (pathname === '/api/export-links' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(shortLinks));
            return;
        }

        // GET /api/export-ticketdb - Export ticket database for backup/sync
        if (pathname === '/api/export-ticketdb' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(ticketDB));
            return;
        }

        // DELETE /api/shorten/:id - Delete a short link
        if (pathname.startsWith('/api/shorten/') && req.method === 'DELETE') {
            const shortId = pathname.split('/')[3];

            if (shortLinks[shortId]) {
                delete shortLinks[shortId];
                saveShortLinks();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Short link deleted' }));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Short link not found' }));
            }
            return;
        }

        // GET /api/tickets/:orderId/:ticketId - Get ticket by order and ticket ID (old CSV format)
        if (pathname.startsWith('/api/tickets/') && req.method === 'GET') {
            const parts = pathname.split('/');
            const orderId = parts[3];
            const ticketId = parts[4];

            // Check if we have this order in the database
            if (ticketDB[orderId]) {
                const orderTickets = ticketDB[orderId];

                if (ticketId) {
                    // Find specific ticket by ID
                    const ticket = orderTickets.find(t => t.id === ticketId);
                    if (ticket) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({
                            success: true,
                            tickets: [ticket]
                        }));
                    } else {
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Ticket not found in order' }));
                    }
                } else {
                    // Return all tickets for order
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        tickets: orderTickets
                    }));
                }
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Order not found' }));
            }
            return;
        }

        // GET /api/stats - Get statistics
        if (pathname === '/api/stats' && req.method === 'GET') {
            const tokenList = Object.values(tokens);
            const stats = {
                total: tokenList.length,
                by_source: {
                    extension: tokenList.filter(t => t.source === 'extension' || t.source === 'web').length,
                    mitmproxy: tokenList.filter(t => t.source === 'mitmproxy' || t.source === 'proxy').length,
                    other: tokenList.filter(t => !['extension', 'web', 'mitmproxy', 'proxy'].includes(t.source)).length
                },
                by_event: {}
            };

            // Group by event
            tokenList.forEach(t => {
                const event = t.event_name || t.eventName || 'Unknown';
                stats.by_event[event] = (stats.by_event[event] || 0) + 1;
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, stats }));
            return;
        }

        // GET /health - Health check
        if (pathname === '/health') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'ok',
                tokens: Object.keys(tokens).length,
                uptime: process.uptime()
            }));
            return;
        }

        // Serve dashboard HTML
        if (pathname === '/' || pathname === '/dashboard') {
            const dashboardPath = path.join(__dirname, 'dashboard.html');
            if (fs.existsSync(dashboardPath)) {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(fs.readFileSync(dashboardPath));
                return;
            }
        }

        // 404 for unknown routes
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));

    } catch (e) {
        console.error('Request error:', e);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
    }
}

// Create server
const server = http.createServer(handleRequest);

// Periodic alert check (every hour)
let alertCheckInterval = null;

function startAlertChecker() {
    // Check every hour
    alertCheckInterval = setInterval(async () => {
        const alerts = checkUpcomingEvents();
        if (alerts.length > 0) {
            await sendAlertEmail(alerts);
        }
    }, 60 * 60 * 1000); // 1 hour

    // Also check on startup after a short delay
    setTimeout(async () => {
        const alerts = checkUpcomingEvents();
        if (alerts.length > 0) {
            console.log(`[Alerts] Found ${alerts.length} events within alert window on startup`);
            await sendAlertEmail(alerts);
        }
    }, 5000);
}

// Login page HTML
function getLoginPage() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SafeTix Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(255,255,255,0.95);
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #1a1a2e;
            margin-bottom: 10px;
            font-size: 24px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #026cdf;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #026cdf;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #0256b3;
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .error.show { display: block; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🎫 SafeTix Admin</h1>
        <p class="subtitle">Enter password to access the dashboard</p>

        <div class="error" id="error"></div>

        <form id="loginForm">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autofocus>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('error');

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });

                const data = await response.json();

                if (data.success) {
                    window.location.href = '/dashboard';
                } else {
                    errorEl.textContent = data.error || 'Invalid password';
                    errorEl.classList.add('show');
                }
            } catch (err) {
                errorEl.textContent = 'Connection error';
                errorEl.classList.add('show');
            }
        });
    </script>
</body>
</html>`;
}

// Start server
loadData();
loadAuthConfig();
server.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║           SafeTix Token Server - Hybrid Capture            ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Server running at: http://localhost:${PORT}                  ║`);
    console.log(`║  Dashboard:         http://localhost:${PORT}/dashboard         ║`);
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  Token Endpoints:                                          ║');
    console.log('║    GET  /api/tokens      - List all captured tokens       ║');
    console.log('║    POST /api/tokens      - Add new token(s)               ║');
    console.log('║    GET  /api/links       - Generate links for all tokens  ║');
    console.log('║    GET  /api/stats       - View capture statistics        ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  Short Link Endpoints:                                     ║');
    console.log('║    POST /api/shorten         - Create a short link        ║');
    console.log('║    GET  /api/shorten/:id     - Get ticket data from link  ║');
    console.log('║    GET  /api/shorten         - List all short links       ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  Barcodeless Link Endpoints:                               ║');
    console.log('║    GET  /api/barcodeless     - List saved barcodeless links║');
    console.log('║    POST /api/barcodeless     - Save a barcodeless link    ║');
    console.log('║    GET  /api/alerts/config   - Get alert settings         ║');
    console.log('║    POST /api/alerts/config   - Configure email alerts     ║');
    console.log('║    GET  /api/alerts/check    - Check for upcoming events  ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  Sources:                                                  ║');
    console.log('║    - Chrome/Firefox Extension (web capture)               ║');
    console.log('║    - mitmproxy (mobile app capture)                       ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`Barcodeless links: ${Object.keys(barcodelessLinks).length}`);
    console.log(`Short links: ${Object.keys(shortLinks).length}`);
    console.log(`Alert email: ${alertConfig.email || 'Not configured'}`);
    console.log('');
    console.log('Waiting for tokens...');
    console.log('');

    // Start the alert checker
    startAlertChecker();
});
