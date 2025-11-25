const fs = require('fs');

try {
    // 1. Read the file
    const csv = fs.readFileSync('data.csv', 'utf8');
    
    // 2. Split into lines (handle Windows or Mac line endings)
    const lines = csv.split(/\r?\n/).filter(line => line.trim() !== '');

    // Remove Header Row
    lines.shift();

    const database = {};

    // --- SMART PARSER FUNCTION ---
    // This correctly handles "Quoted, Fields" and ignores commas inside them
    function parseCSVLine(text) {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            
            if (char === '"') {
                inQuotes = !inQuotes; // Toggle "Inside Quotes" mode
            } else if (char === ',' && !inQuotes) {
                // If we see a comma and are NOT in quotes, that's a new field
                result.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        // Push the last field
        result.push(current.trim());
        return result;
    }

    // 3. Process Each Line
    lines.forEach((line, index) => {
        const columns = parseCSVLine(line);

        // Make sure we have enough columns (at least 7)
        if (columns.length < 7) {
            console.log(`⚠️ Skipping Line ${index + 2}: Not enough data.`);
            return;
        }

        // MAPPING (Based on your Excel structure)
        // Col A = Order ID
        // Col B = Ticket ID
        // Col C = Event
        // Col D = Date
        // Col E = Sec
        // Col F = Row
        // Col G = Seat
        // Col H = Location
        const orderId = columns[0];
        const ticketId = columns[1];
        const eventName = columns[2].replace(/^"|"$/g, ''); // Remove extra quotes if present
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
            // Generate the wallet link automatically
            wallet_url: `https://secured-ticket-access.com/ticket-${ticketId}.pkpass`
        });
    });

    // 4. Save Output
    fs.writeFileSync('output.json', JSON.stringify(database, null, 2));
    console.log("✅ Success! Created output.json with correct event names.");

} catch (err) {
    console.error("❌ Error:", err.message);
}