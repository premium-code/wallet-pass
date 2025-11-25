const fs = require('fs');
const { PKPass } = require('passkit-generator');
const path = require('path');

async function generateAll() {
    try {
        console.log("1. Reading CSV...");
        const csv = fs.readFileSync('data.csv', 'utf8');
        const lines = csv.split(/\r?\n/).filter(line => line.trim() !== '');
        lines.shift(); // Remove header

        // --- NEW: Create the output folder if it doesn't exist ---
        const outputDir = './passes';
        if (!fs.existsSync(outputDir)){
            fs.mkdirSync(outputDir);
        }

        const certs = {
            wwdr: fs.readFileSync('./wwdr.pem'),
            signerCert: fs.readFileSync('./pass.pem'),
            signerKey: fs.readFileSync('./private.key'),
        };

        function parseCSVLine(text) {
            const result = [];
            let current = '';
            let inQuotes = false;
            for (let i = 0; i < text.length; i++) {
                const char = text[i];
                if (char === '"') { inQuotes = !inQuotes; }
                else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; }
                else { current += char; }
            }
            result.push(current.trim());
            return result;
        }

        console.log("2. Generating Passes into 'passes' folder...");

        for (const line of lines) {
            const cols = parseCSVLine(line);
            if (cols.length < 7) continue;

            const id      = cols[1];
            const event   = cols[2].replace(/^"|"$/g, '');
            const date    = cols[3].replace(/^"|"$/g, '');
            const sec     = cols[4];
            const seat    = cols[6];
            const loc     = cols[7] || "Sanford Stadium";

            const pass = await PKPass.from({
                model: './pass-model.pass',
                certificates: certs
            }, {
                serialNumber: id,
                description: event,
                eventTicket: {
                    primaryFields: [ { key: 'event', label: 'EVENT', value: event.toUpperCase