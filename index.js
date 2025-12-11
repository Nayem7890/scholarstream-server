// index.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;

// ---------- Middlewares ----------
app.use(
  cors({
    origin: [
      "http://localhost:5173",              // Vite dev
      // "https://your-frontend-domain.vercel.app"
    ],
    credentials: true,
  })
);
app.use(express.json());

// ---------- MongoDB Client ----------
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("scholarstream");
    const usersCollection = db.collection("users");
    const scholarshipsCollection = db.collection("scholarships");
    const applicationsCollection = db.collection("applications");
    const reviewsCollection = db.collection("reviews");

    // ---------- MIDDLEWARES (inside run so they can use collections) ----------

    // Verify JWT
const verifyJWT = (req, res, next) => {
  console.log("Authorization header from client:", req.headers.authorization);

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: "Unauthorized: No token" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("JWT verify error:", err.message);
      return res.status(403).send({ message: "Forbidden: Invalid token" });
    }
    req.decoded = decoded; // { email: ... }
    next();
  });
};


    // Verify Admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded?.email;
      if (!email) {
        return res.status(401).send({ message: "Unauthorized" });
      }

      const user = await usersCollection.findOne({ email });
      if (user?.role !== "Admin") {
        return res.status(403).send({ message: "Forbidden: Admin only" });
      }
      next();
    };

    // Verify Moderator
    const verifyModerator = async (req, res, next) => {
      const email = req.decoded?.email;
      if (!email) {
        return res.status(401).send({ message: "Unauthorized" });
      }

      const user = await usersCollection.findOne({ email });
      if (user?.role !== "Moderator") {
        return res.status(403).send({ message: "Forbidden: Moderator only" });
      }
      next();
    };

    // ---------- BASIC TEST ROUTE ----------
    app.get("/", (req, res) => {
      res.send("ScholarStream Server Running");
    });

    // =====================================================
    //  AUTH & USERS
    // =====================================================

    // Create JWT token (called from frontend after Firebase login)
    app.post("/jwt", (req, res) => {
      const user = req.body; // { email }
      const token = jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });
      res.send({ token });
    });

    // Save user (on register / first login)
    app.post("/users", async (req, res) => {
      const user = req.body; // { name, email, photoURL, role? }

      const existing = await usersCollection.findOne({ email: user.email });
      if (existing) {
        return res.send({ message: "User already exists", insertedId: null });
      }

      // Default role Student
      if (!user.role) {
        user.role = "Student";
      }

      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    // Get all users (Admin only, with optional role filter)
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const role = req.query.role;
      const query = role ? { role } : {};
      const result = await usersCollection.find(query).toArray();
      res.send(result);
    });

    // Get my user info
    app.get("/users/me", verifyJWT, async (req, res) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email });
      res.send(user);
    });

    // Get role by email (for useRole() hook)
    app.get("/users/role/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden" });
      }
      const user = await usersCollection.findOne({ email });
      res.send({ role: user?.role || "Student" });
    });

    // Change user role (Admin)
    app.patch("/users/role/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body; // 'Admin' | 'Moderator' | 'Student'
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } }
      );
      res.send(result);
    });

    // Delete user (Admin)
    app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // =====================================================
    //  SCHOLARSHIPS (Public + Admin)
    // =====================================================

    // All scholarships with search, filter, sort, pagination
    app.get("/scholarships", async (req, res) => {
      try {
        const search = req.query.search || "";
        const degree = req.query.degree || "";
        const country = req.query.country || "";
        const category = req.query.category || ""; // scholarshipCategory
        const sortBy = req.query.sortBy || "scholarshipPostDate"; // or "applicationFees"
        const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const filter = {};

        if (search) {
          filter.$or = [
            { scholarshipName: { $regex: search, $options: "i" } },
            { universityName: { $regex: search, $options: "i" } },
            { degree: { $regex: search, $options: "i" } },
          ];
        }

        if (degree) filter.degree = degree;
        if (country) filter.universityCountry = country;
        if (category) filter.scholarshipCategory = category;

        const sortOptions = {};
        if (sortBy === "applicationFees" || sortBy === "scholarshipPostDate") {
          sortOptions[sortBy] = sortOrder;
        }

        const total = await scholarshipsCollection.countDocuments(filter);
        const data = await scholarshipsCollection
          .find(filter)
          .sort(sortOptions)
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          data,
          total,
          page,
          totalPages: Math.ceil(total / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching scholarships" });
      }
    });

    // Top scholarships (for Home page)
    app.get("/scholarships/top", async (req, res) => {
      const data = await scholarshipsCollection
        .find({})
        .sort({ applicationFees: 1, scholarshipPostDate: -1 })
        .limit(6)
        .toArray();
      res.send(data);
    });

    // Get scholarship by ID
    app.get("/scholarships/:id", async (req, res) => {
      const id = req.params.id;
      const result = await scholarshipsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Add scholarship (Admin)
    app.post("/scholarships", verifyJWT, verifyAdmin, async (req, res) => {
      const scholarship = req.body;
      const result = await scholarshipsCollection.insertOne(scholarship);
      res.send(result);
    });

    // Update scholarship (Admin)
    app.patch("/scholarships/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const update = req.body;
      const result = await scholarshipsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: update }
      );
      res.send(result);
    });

    // Delete scholarship (Admin)
    app.delete(
      "/scholarships/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const result = await scholarshipsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      }
    );

    // =====================================================
    //  APPLICATIONS (Student + Moderator)
    // =====================================================

    // Create application (called after payment success/fail)
    app.post("/applications", verifyJWT, async (req, res) => {
      const application = req.body;
      application.applicationDate = application.applicationDate || new Date();
      application.applicationStatus = application.applicationStatus || "pending";
      application.paymentStatus = application.paymentStatus || "unpaid";

      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });

    // Get my applications (Student)
    app.get("/applications/me", verifyJWT, async (req, res) => {
      const email = req.decoded.email;
      const result = await applicationsCollection
        .find({ userEmail: email })
        .toArray();
      res.send(result);
    });

    // Get all applications (Moderator)
    app.get(
      "/applications",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const result = await applicationsCollection.find().toArray();
        res.send(result);
      }
    );

    // Update application status / feedback (Moderator)
    app.patch(
      "/applications/:id/status",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const id = req.params.id;
        const { applicationStatus, feedback } = req.body;
        const updateDoc = {};
        if (applicationStatus) updateDoc.applicationStatus = applicationStatus;
        if (feedback !== undefined) updateDoc.feedback = feedback;

        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );
        res.send(result);
      }
    );

    // Update payment status (Student retry payment)
    app.patch("/applications/:id/payment", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const { paymentStatus } = req.body; // 'paid' | 'unpaid'
      const result = await applicationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { paymentStatus } }
      );
      res.send(result);
    });

    // Delete application (Student, only if pending)
    app.delete("/applications/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      // Optional: verify status is pending first (you can enforce from frontend)
      const result = await applicationsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Get single application by id (for Payment Success page)
    app.get("/applications/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const result = await applicationsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // =====================================================
    //  REVIEWS (Student + Moderator)
    // =====================================================

    // Add review (Student, only if application completed – enforce in frontend or check here)
    app.post("/reviews", verifyJWT, async (req, res) => {
      const review = req.body;
      review.reviewDate = review.reviewDate || new Date();
      const result = await reviewsCollection.insertOne(review);
      res.send(result);
    });

    // Get reviews for a scholarship
    app.get("/reviews", async (req, res) => {
      const { scholarshipId, userEmail } = req.query;
      const query = {};
      if (scholarshipId) query.scholarshipId = scholarshipId;
      if (userEmail) query.userEmail = userEmail;
      const result = await reviewsCollection.find(query).toArray();
      res.send(result);
    });

    // Get my reviews (Student)
    app.get("/reviews/me", verifyJWT, async (req, res) => {
      const email = req.decoded.email;
      const result = await reviewsCollection
        .find({ userEmail: email })
        .toArray();
      res.send(result);
    });

    // Update review (Student)
    app.patch("/reviews/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const { ratingPoint, reviewComment } = req.body;
      const result = await reviewsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { ratingPoint, reviewComment } }
      );
      res.send(result);
    });

    // Delete review (Student own OR Moderator)
    app.delete("/reviews/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      // For simplicity: let Moderator delete any, Student delete own – you can check role+email if you want.
      const result = await reviewsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Moderator: get all reviews
    app.get(
      "/moderator/reviews",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const result = await reviewsCollection.find().toArray();
        res.send(result);
      }
    );

    // =====================================================
    //  PAYMENTS (Stripe)
    // =====================================================

    // Create Payment Intent
    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      const { applicationFees, serviceCharge } = req.body;

      const total =
        (Number(applicationFees) || 0) + (Number(serviceCharge) || 0);
      const amount = Math.round(total * 100); // Stripe needs cents

      if (!amount || amount <= 0) {
        return res
          .status(400)
          .send({ message: "Invalid payment amount", amount });
      }

      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    // =====================================================
    //  ANALYTICS (Admin – example)
    // =====================================================

    app.get("/analytics/overview", verifyJWT, verifyAdmin, async (req, res) => {
      const totalUsers = await usersCollection.estimatedDocumentCount();
      const totalScholarships =
        await scholarshipsCollection.estimatedDocumentCount();
      const totalApplications =
        await applicationsCollection.estimatedDocumentCount();

      // Example: total fees collected (sum of applicationFees where paymentStatus=paid)
      const paidApps = await applicationsCollection
        .aggregate([
          { $match: { paymentStatus: "paid" } },
          {
            $group: {
              _id: null,
              totalFees: { $sum: "$applicationFees" },
            },
          },
        ])
        .toArray();

      const totalFeesCollected = paidApps[0]?.totalFees || 0;

      res.send({
        totalUsers,
        totalScholarships,
        totalApplications,
        totalFeesCollected,
      });
    });
  } catch (error) {
    console.error("Mongo Connection Error:", error);
  }
}

run().catch(console.dir);

// ---------- Start Server ----------
app.listen(port, () => {
  console.log(`ScholarStream server listening on port ${port}`);
});
