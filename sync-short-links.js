/**
 * sync-short-links.js
 *
 * Pulls every short-link record from the VPS token server and writes a single
 * static JSON file (short-links.json) next to index.html.
 *
 * Why: the live HTTPS fronting cert (api.secured-ticket-access.com) expired,
 * so the page can't fetch from the API anymore. GitHub Pages serves this JSON
 * over HTTPS from the same origin as the site, so no cert renewal needed.
 *
 * Run whenever you create new short links on the VPS:
 *   node sync-short-links.js
 *
 * Env:
 *   VPS_URL   - override VPS base URL (default http://167.71.166.224:3847)
 *   OUT_FILE  - override output path (default ./short-links.json)
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const VPS_URL = process.env.VPS_URL || 'http://167.71.166.224:3847';
const OUT_FILE = process.env.OUT_FILE || path.join(__dirname, 'short-links.json');
const CONCURRENCY = 8;

function fetchJson(url) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const client = u.protocol === 'https:' ? https : http;
        const req = client.request({
            hostname: u.hostname,
            port: u.port || (u.protocol === 'https:' ? 443 : 80),
            path: u.pathname + u.search,
            method: 'GET',
            headers: { 'Accept': 'application/json', 'User-Agent': 'sync-short-links/1.0' },
            timeout: 15000
        }, (res) => {
            let data = '';
            res.on('data', (c) => data += c);
            res.on('end', () => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
                }
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(new Error(`Invalid JSON from ${url}: ${e.message}`)); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${url}`)); });
        req.end();
    });
}

async function mapWithConcurrency(items, limit, fn) {
    const results = new Array(items.length);
    let next = 0;
    async function worker() {
        while (true) {
            const i = next++;
            if (i >= items.length) return;
            try { results[i] = await fn(items[i], i); }
            catch (e) { results[i] = { error: e.message }; }
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
    return results;
}

(async () => {
    console.log(`[sync] Listing short links from ${VPS_URL}/api/shorten ...`);
    const list = await fetchJson(`${VPS_URL}/api/shorten`);
    if (!list || !list.success || !Array.isArray(list.links)) {
        throw new Error('Unexpected response from /api/shorten');
    }
    console.log(`[sync] Found ${list.links.length} short links. Fetching each...`);

    const detailResults = await mapWithConcurrency(list.links, CONCURRENCY, async (link) => {
        const detail = await fetchJson(`${VPS_URL}/api/shorten/${encodeURIComponent(link.id)}`);
        return { id: link.id, detail };
    });

    const byId = {};
    let ok = 0, fail = 0;
    for (const r of detailResults) {
        if (!r || r.error) { fail++; continue; }
        if (r.detail && r.detail.success) {
            byId[r.id] = {
                success: true,
                tickets: r.detail.tickets,
                createdAt: r.detail.createdAt,
                accessCount: r.detail.accessCount
            };
            ok++;
        } else {
            fail++;
        }
    }

    const payload = {
        generatedAt: new Date().toISOString(),
        source: VPS_URL,
        count: ok,
        links: byId
    };

    fs.writeFileSync(OUT_FILE, JSON.stringify(payload, null, 2));
    console.log(`[sync] Wrote ${ok} records to ${OUT_FILE} (${fail} failed)`);
})().catch((e) => {
    console.error('[sync] FAILED:', e.message);
    process.exit(1);
});
