const { PKPass } = require('passkit-generator');
const fs = require('fs');

async function createPass() {
  try {
    console.log("Loading certificates...");
    const certs = {
      wwdr: fs.readFileSync('./wwdr.pem'),
      signerCert: fs.readFileSync('./pass.pem'),
      signerKey: fs.readFileSync('./private.key'),
      // signerKeyPassphrase: '1234' // Uncomment if needed
    };

    console.log("Reading pass-model.pass...");
    // Just load the folder and sign it. No data injection.
    const pass = await PKPass.from({
      model: './pass-model.pass',
      certificates: certs
    });

    console.log("Generating file...");
    const buffer = pass.getAsBuffer();
    fs.writeFileSync('ticket-1001.pkpass', buffer);
    
    console.log("✅ SUCCESS! ticket-1001.pkpass created.");

  } catch (error) {
    console.error("❌ ERROR FAILED:", error);
  }
}

createPass();