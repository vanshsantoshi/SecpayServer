const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
app.use(bodyParser.json());

// In-memory DB (replace with real DB later)
const devices = new Map();

/*
 Utility: canonicalize JSON
 - Sort keys
 - No whitespace
 - MUST match Android canonicalisation
*/
function canonicalize(obj) {
  const sorted = {};
  Object.keys(obj)
    .sort()
    .forEach(k => {
      sorted[k] = obj[k];
    });
  return JSON.stringify(sorted);
}

app.post("/registerDevice", (req, res) => {
  const { device_id, public_key, hardware_backed, cert_chain } = req.body;

  if (!device_id || !public_key) {
    return res.status(400).json({ error: "missing fields" });
  }

  devices.set(device_id, {
    publicKeyBase64: public_key,
    hardwareBacked: !!hardware_backed,
    certChain: cert_chain || []
  });

  console.log("Registered device:", device_id);
  console.log("Hardware-backed:", hardware_backed);

  res.json({ registered: true });
});


app.post("/submitIntentProof", (req, res) => {
  try {
    const { device_id, intent_payload, signature } = req.body;

    if (!device_id || !intent_payload || !signature) {
      return res.json({ verified: false });
    }

    const device = devices.get(device_id);
    if (!device) {
      return res.json({ verified: false });
    }

    // Canonicalize payload (MUST match Android)
    const canonicalPayload = canonicalize(intent_payload);

    const publicKeyDer = Buffer.from(device.publicKeyBase64, "base64");

    const verify = crypto.createVerify("SHA256");
    verify.update(canonicalPayload);
    verify.end();

    const isValid = verify.verify(
      {
        key: publicKeyDer,
        format: "der",
        type: "spki"
      },
      Buffer.from(signature, "base64")
    );

    return res.json({ verified: isValid });

  } catch (e) {
    return res.json({ verified: false });
  }
});


app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});