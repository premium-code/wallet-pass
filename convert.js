const fs = require('fs');

try {
    // 1. Read the input file
    const csv = fs.readFileSync('data.csv', 'utf8');
    const lines = csv.split(/\r?\n/).filter(line => line.trim() !== '');
    lines.shift(); // Remove headers

    const database = {};
    let linkExport = "Order ID,Ticket ID,Event,Web Link,Wallet Link\n"; // CSV Header

    // --- HELPER: SMART CSV PARSER ---
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

    // 2. Process Lines
    lines.forEach((line) => {
        const col = parseCSVLine(line);
        if (col.length < 7) return;

        const orderId = col[0];
        const id      = col[1];
        const event   = col[2].replace(/^"|"$/g, '');
        const date    = col[3].replace(/^"|"$/g, '');
        const sec     = col[4];
        const row     = col[5];
        const seat    = col[6];
        const loc     = col[7] || "Sanford Stadium";
        
        // Generate the Links
        const walletUrl = `https://secured-ticket-access.com/ticket-${id}.pkpass`;
        const webUrl    = `https://secured-ticket-access.com/?ord=${orderId}&id=${id}`;

        // Add to Database JSON
        if (!database[orderId]) database[orderId] = [];
        database[orderId].push({
            id: id, event: event, date: date, sec: sec, row: row, seat: seat, loc: loc,
            type: "Standard Admission",
            wallet_url: walletUrl
        });

        // Add to Export CSV (Append line)
        linkExport += `${orderId},${id},"${event}",${webUrl},${walletUrl}\n`;
    });

    // 3. Save Files
    fs.writeFileSync('output.json', JSON.stringify(database, null, 2));
    fs.writeFileSync('final_links.csv', linkExport); // <--- NEW FILE CREATED HERE

    console.log("✅ Success! Created 'output.json' (for website) and 'final_links.csv' (for you).");

} catch (err) {
    console.error("❌ Error:", err.message);
}