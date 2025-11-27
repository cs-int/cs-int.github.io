// taken from https://github.com/fahadadnaan/nodemailer-with-google-recaptcha/blob/master/server.js
require('dotenv').config();

const express = require('express');
const logger = require('morgan');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const axios = require('axios');

const PORT = process.env.PORT || 5000;

const app = express();

// Body Parser Middleware
app.use(express.urlencoded({ extended: false }));

app.use(logger('dev'));
app.use(cors());
app.use(xss());
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// rate limite
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 15 minutes
  max: 5,
});
app.use('/', apiLimiter);

const sendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100, // start blocking after this many requests
  message: 'Too many requests from this IP, please try again after 10 minutes',
});

app.post(
  '/mailapp/api/contact',
  sendLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('phone').not().isEmpty().trim().escape(),
    body('name').not().isEmpty().trim().escape(),
    body('message').not().isEmpty().trim().escape(),
    body('recaptcha_response').not().isEmpty().trim().escape(),
  ],
  async (req, res, next) => {
    if (process.env.DEBUG === 'true') {
        // Log a debug statement if DEBUG is true
        console.log('Received form data:', req.body);
      }
   
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    const { name, email, phone, message } = req.body;
    const secretKey = process.env.CAPTCHA_SECRET_KEY;
    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${req.body.recaptcha_response}`;
    axios.post(url).then((data) => {
      console.log(data.data);
      if (!data.data.success) {
        return res.status(422).json({
          status: 422,
          res: data.data,
          msg: 'Please refresh the page if you want to send another message',
        });
      }
      const output = `
<p>You have a new message sent via. the website contact form</p>
<h3>Contact Details</h3>
<ul>  
  <li>Name: ${name}</li>
  <li>Email: ${email}</li>
  <li>Phone: ${phone}</li>
</ul>
<h3>Message</h3> 
<p>${message}</p>
<strong>You can reply to the sender by replying to this email</strong>
`;
      let mailOptions = {
        from: `"Website Contact Form" <${process.env.FROMEMAIL}>`,
        to: process.env.TOEMAIL,
        subject: `Web Contact Form Enquiry - ${name}`,
        replyTo: email,
        html: output,
      };
      let transporter = nodemailer.createTransport({
        host: process.env.HOST,
        port: process.env.MAILPORT,
        auth: {
          user: process.env.USER,
          pass: process.env.PASSWORD,
        },
        debug: true, // show debug output
        logger: true, // log information in console
      });
      try {
        transporter.sendMail(mailOptions, (err, data) => {
          if (err) {
            // Log the error if sending the email fails
            console.error('Error sending email:', err);
            if (process.env.DEBUG === 'true') {
              console.error('Additional debug information:', {
                mailOptions,
                transporterConfig: {
                  host: process.env.HOST,
                  port: process.env.MAILPORT,
                  user: process.env.USER,
                  password: process.env.PASSWORD,
                },
              });
            }
            return next(err);
          }
      
          if (data) {
            if (process.env.DEBUG === 'true') {
              // Log a debug statement if DEBUG is true
              console.log('Email sent successfully:', data);
            }
      
            res.status(200).json({
              status: 200,
              msg: 'Your message was successfully submitted, We will contact you soon..',
              fail: false
            });
            next();
          }
        });
      } catch (error) {
        // Log any other errors that might occur
        console.error('Unexpected error:', error);
        if (process.env.DEBUG === 'true') {
          console.error('Additional debug information:', {
            mailOptions,
            transporterConfig: {
              host: process.env.HOST,
              port: process.env.MAILPORT,
              user: process.env.USER,
              password: process.env.PASSWORD,
            },
          });
        }
        next(error);
      }
    });
  }
);

app.use((error, request, response, next) => {
  response.status(error.status || 500);
  response.json({ error: "Internal Error" });
  next();
});

const server = app.listen(PORT, '0.0.0.0', function () {
    const host = server.address().address;
    const port = server.address().port;
    console.log('App is listening on http://%s:%s', host, port);
});

module.exports = app;