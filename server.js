const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Use raw body parser to capture body before parsing JSON
app.use('/webhook', bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post('/webhook', (req, res) => {
  const signature = req.headers['x-signature'];
  const rawBody = req.rawBody;

  if (!signature) {
    return res.status(400).send('Missing signature header');
  }

  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'))) {
    return res.status(401).send('Invalid signature');
  }

  console.log('✅ Webhook verified:', req.body);
  res.status(200).send('Received and verified');
});

app.listen(PORT, () => {
  console.log(`🚀 Webhook server running at http://localhost:${PORT}/webhook`);
});
