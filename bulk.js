const { PKPass } = require('passkit-generator');
const fs = require('fs');

// 1. YOUR TICKET LIST (Paste your Excel data here)
const tickets = [
  { id: '1001', event: 'The Eras Tour', sec: 'VIP', row: '1', seat: '12', loc: 'Floor' },
  { id: '1002', event: 'The Eras Tour', sec: 'VIP', row: '1', seat: '13', loc: 'Floor' },
  { id: '1003', event: 'The Eras Tour', sec: '104', row: 'B', seat: '5',  loc: 'Lower Bowl' }
];

async function generateAll() {
  console.log(`Starting generation for ${tickets.length} tickets...`);

  const certs = {
    wwdr: fs.readFileSync('./wwdr.pem'),
    signerCert: fs.readFileSync('./pass.pem'),
    signerKey: fs.readFileSync('./private.key'),
  };

  for (const ticket of tickets) {
    try {
      // Create the pass using the specific details for THIS ticket
      const pass = await PKPass.from({
        model: './pass-model.pass',
        certificates: certs
      }, {
        serialNumber: ticket.id, // Unique ID is crucial
        description: ticket.event,
        eventTicket: {
          headerFields: [
            { key: 'date', label: 'DATE', value: 'NOV 29' }
          ],
          primaryFields: [
            { key: 'event', label: 'EVENT', value: ticket.event.toUpperCase() }
          ],
          secondaryFields: [
            { key: 'sec', label: 'SEC', value: ticket.sec },
            { key: 'seat', label: 'SEAT', value: ticket.seat }
          ],
          auxiliaryFields: [
            { key: 'loc', label: 'LOCATION', value: ticket.loc }
          ]
        }
      });

      const buffer = pass.getAsBuffer();
      fs.writeFileSync(`ticket-${ticket.id}.pkpass`, buffer);
      console.log(`✅ Generated ticket-${ticket.id}.pkpass`);

    } catch (err) {
      console.error(`❌ Failed ticket ${ticket.id}:`, err);
    }
  }
}

generateAll();