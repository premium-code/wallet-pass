const fs = require('fs');

try {
    // 1. Read the file
    const csv = fs.readFileSync('data.csv', 'utf8');
    
    // 2. Split into lines
    const lines = csv.split(/\r?\n/).filter(line => line.trim() !== '');

    // Remove Header Row
    lines.shift();

    const database = {};

    // --- SMART PARSER FUNCTION ---
    function parseCSVLine(text) {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (char === '"') {
                inQuotes = !inQuotes; 
            } else if (char === ',' && !inQuotes) {
                result.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        result.push(current.trim());
        return result;
    }

    // 3. Process Each Line
    lines.forEach((line, index) => {
        const columns = parseCSVLine(line);

        if (columns.length < 7) {
            return;
        }

        // MAPPING
        const orderId = columns[0];
        const ticketId = columns[1];
        const eventName = columns[2].replace(/^"|"$/g, ''); 
        const date = columns[3].replace(/^"|"$/g, '');
        const sec = columns[4];
        const row = columns[5];
        const seat = columns[6];
        const loc = columns[7] || "Sanford Stadium";

        if (!database[orderId]) {
            database[orderId] = [];
        }

        database[orderId].push({
            id: ticketId,
            event: eventName,
            date: date,
            sec: sec,
            row: row,
            seat: seat,
            loc: loc,
            type: "Standard Admission",
            wallet_url: `https://secured-ticket-access.com/ticket-${ticketId}.pkpass`
        });
    });

    // 4. Save Output
    fs.writeFileSync('output.json', JSON.stringify(database, null, 2));
    console.log("✅ Success! Created output.json.");

} catch (err) {
    console.error("❌ Error:", err.message);
}