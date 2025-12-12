# ScholarStream Server (Backend API)

ScholarStream is a Scholarship Management Platform. This repository contains the **backend (Node.js/Express API)** that powers authentication, role-based access (Admin/Moderator/Student), scholarship management, applications, reviews, payments (Stripe), and analytics.


## Purpose

The backend provides:
- Secure REST APIs for the ScholarStream client
- JWT-based authentication & role-based authorization
- CRUD operations for Scholarships
- Application workflow management (Pending → Processing → Completed/Rejected)
- Review system for students
- Stripe Payment Intent integration
- Admin analytics for dashboard statistics

---

## Live Server URL

- **Production API:** https://scholar-stream-server-sooty.vercel.app/

### Useful Endpoints (Quick Check)
- `GET /` → Server health check
- `GET /scholarships` → Public scholarships list (search/filter/sort/pagination)
- `POST /jwt` → Create JWT token
- `POST /create-payment-intent` → Stripe payment intent (JWT required)

---

## Main Technologies Used

- **Node.js**
- **Express.js**
- **MongoDB Atlas**
- **JWT (jsonwebtoken)**
- **Stripe Payment API**
- **CORS**
- **dotenv**
- Deployed on **Vercel**

---

## Core Features

### Authentication & Security
- JWT token generation (`POST /jwt`)
- Protected routes using `verifyJWT`
- Role-based authorization:
  - `verifyAdmin` for Admin-only routes
  - `verifyModerator` for Moderator-only routes

### Users
- Create/save user on first login (`POST /users`)
- Admin can:
  - Fetch all users with optional role filtering (`GET /users?role=Student`)
  - Update user role (`PATCH /users/:id/role`)
  - Delete user (`DELETE /users/:id`)

### Scholarships
- Public:
  - List scholarships with search, filter, sort, and pagination (`GET /scholarships`)
  - Top 6 scholarships (`GET /scholarships/top`)
  - Details (`GET /scholarships/:id`)
- Admin:
  - Add (`POST /scholarships`)
  - Update (`PATCH /scholarships/:id`)
  - Delete (`DELETE /scholarships/:id`)

### Applications
- Student:
  - Create application (`POST /applications`)
  - Get own applications (`GET /applications/me`)
  - Retry payment update (`PATCH /applications/:id/payment`)
  - Delete application (`DELETE /applications/:id`)
- Moderator/Admin:
  - Get all applications (`GET /applications`)
  - Update status + feedback (`PATCH /applications/:id/status`)

### Reviews
- Student:
  - Add review (`POST /reviews`)
  - Get own reviews (`GET /reviews/me`)
  - Update review (`PATCH /reviews/:id`)
  - Delete review (`DELETE /reviews/:id`)
- Public:
  - Get reviews by scholarship (`GET /reviews?scholarshipId=...`)
- Moderator:
  - Get all reviews (`GET /moderator/reviews`)

### Payments (Stripe)
- Create Payment Intent (`POST /create-payment-intent`)  
  Uses scholarship fees + service charge, converts total to cents, and returns `clientSecret`.

### Analytics (Admin)
- Dashboard analytics (`GET /analytics`)
  - totalUsers, totalScholarships, totalApplications
  - totalRevenue (sum of paid application fees)
  - topScholarships (by application count)
  - recentApplications (formatted for frontend)
  - usersByRole distribution

---

## NPM Packages / Dependencies Used

Main dependencies commonly used in this backend:
- `express`
- `cors`
- `mongodb`
- `dotenv`
- `jsonwebtoken`
- `stripe`

(If you want, you can paste your `package.json` here and list them exactly.)

---

## Environment Variables

Create a `.env` file in the server root:

```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
STRIPE_SECRET_KEY=your_stripe_secret_key
PORT=3000
How to Run Locally
1) Clone the repository
bash
Copy code
git clone <your-server-repo-url>
cd <your-server-folder>
2) Install dependencies
bash
Copy code
npm install
3) Setup environment variables
Create .env and add the variables described above.

4) Start the server
bash
Copy code
npm run start
Server will run on:

http://localhost:3000

Deployment Notes (Vercel)
This server is deployed on Vercel as a serverless Express API.

Make sure these are set in Vercel Project → Settings → Environment Variables:

MONGODB_URI

JWT_SECRET

STRIPE_SECRET_KEY

Related Links
Client (Frontend): https://scholarstream-client.vercel.app/

Server (API): https://scholar-stream-server-sooty.vercel.app/



Author / Project Info
ScholarStream is built as a MERN-based Scholarship Management Platform where:

Students apply for scholarships by paying application fees

Moderators review applications and update status with feedback

Admins manage scholarships, users, and analytics
