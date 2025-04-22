# 🏔️ Treker – Trek Booking Platform

Treker is a demo Node.js-based web application where users can register, select treks, specify the number of guests, and complete a payment using Razorpay. The booking details are stored in a MySQL database, and a confirmation email is sent to the user.

---

## 📦 Features

- User-friendly booking form with trek options and guest selection
- Payment gateway integration using Razorpay
- Email confirmation after successful booking (via Nodemailer + Gmail)
- Bookings stored in MySQL using Sequelize ORM
- SweetAlerts used for beautiful alert popups

---

## 🛠️ Technologies Used

- Node.js + Express.js
- MySQL + Sequelize ORM
- Razorpay Integration
- Nodemailer (for email)
- HTML + CSS + Bootstrap (Frontend)
- SweetAlert2
- JavaScript (Vanilla)

---

## 🚀 Installation & Setup Guide

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/treker.git
cd treker
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables
#### Create a .env file in the root directory and add the following:

```bash
PORT=5000

# Database credentials
DB_HOST=localhost
DB_NAME=treker
DB_USER=root
DB_PASS=

# Razorpay Keys
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret

# Nodemailer (Gmail)
EMAIL_USER=your.email@gmail.com
EMAIL_PASS=your_generated_app_password
```

#### Enable 2-Step Verification on your Gmail account.
#### Go to https://myaccount.google.com/apppasswords
#### Generate an App Password for "Mail" → "Other" (name it TrekerApp or whatever).
#### Copy the password and update .env

## 🔧 Generate a JWT Secret

### Run this in your terminal:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Copy it and paste into your .env file:
```bash
JWT_SECRET=d6f8c09b7f3c4e1f992d3c8e54b0a2b3a0a0b9d1...
```

## 💾 Database Setup

### 1. Create a database in MySQL:

```bash
CREATE DATABASE treker;
```
#### Mention this in the .env file
#### Sequelize will auto-create required tables on server start (based on models).

## 🧪 Run the Project

```bash
npm run dev
```

#### Visit: http://localhost:5000

### 📧 Email Confirmation

#### After a successful payment:
#### Booking is stored in DB
#### A confirmation email is sent to the provided email

### 📁 Folder Structure

```bash
.
├── config/               
│   └── db.js
├── controllers/            
│   └── userController.js
├── middlewares/              
│   └── authMiddleware.js              
├── models/             
│   └── Booking.js            
│   └── index.js            
│   └── User.js
├── node_modules/       # this will be created when you run npm install command 
├── public/            
│   └── css/
│   └── fonts/
│   └── images/
│   └── js/         
│   ├── index.html
│   ├── packages.html
│   ├── checkout.html
│   ├── # & other html files
├── routes/            
│   └── bookings.js     
│   └── pay.js     
│   └── razorpay.js     
│   └── userRoutes.js
├── utils/          
│   └── mailer.js  
├── views/
├── .env
├── .gitignore
├── app.js
├── package-lock.json
├── package.json
├── README.md
└── server.js
```