const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post('/api/sendMail', async (req, res) => {
  const { name, email, mobile, date, from, to, requirement } = req.body || {};

  if (!name || !email || !requirement) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    await sgMail.send({
      to: process.env.EMAIL_USER,
      from: process.env.EMAIL_USER,
      replyTo: email,
      subject: `TTC enquiry from ${name}`,
      text: `
Name: ${name}
Email: ${email}
Mobile: ${mobile || 'N/A'}
From: ${from || 'N/A'}
To: ${to || 'N/A'}
Date: ${date || 'N/A'}

Requirement:
${requirement}
      `,
    });

    res.json({ success: true, message: "Message sent successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Email failed" });
  }
});
