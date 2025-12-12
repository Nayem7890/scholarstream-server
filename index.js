// index.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;


// Global Middlewares

app.use(
  cors({
    origin: [
      "http://localhost:5173", // Vite dev
      // "https://your-frontend-domain.vercel.app",
    ],
    credentials: true,
  })
);
app.use(express.json());


// MongoDB Client

const uri = process.env.MONGODB_URI;

if (!uri) {
  console.error("❌ MONGODB_URI is not set in .env");
  process.exit(1);
}

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
    console.log("✅ Connected to MongoDB");

    const db = client.db("scholarstream");
    const usersCollection = db.collection("users");
    const scholarshipsCollection = db.collection("scholarships");
    const applicationsCollection = db.collection("applications");
    const reviewsCollection = db.collection("reviews");

    // ---------------------------
    // Auth Middlewares
    // ---------------------------
    const verifyJWT = (req, res, next) => {
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
        req.decoded = decoded; // e.g. { email: "..." }
        next();
      });
    };

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

    // ---------------------------
    // Basic Health Route
    // ---------------------------
    app.get("/", (req, res) => {
      res.send("ScholarStream Server Running");
    });

    // =====================================================
    //  AUTH & USERS
    // =====================================================

    // Create JWT token (called from frontend after Firebase login)
    app.post("/jwt", (req, res) => {
      const user = req.body; // { email }
      if (!user?.email) {
        return res.status(400).send({ message: "Email is required" });
      }

      const token = jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });
      res.send({ token });
    });

    // Save user (on register / first login)
    app.post("/users", async (req, res) => {
      try {
        const user = req.body; // { name, email, photoURL, role? }

        if (!user?.email) {
          return res.status(400).send({ message: "Email is required" });
        }

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
      } catch (error) {
        console.error("Error saving user:", error);
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    // Get all users (Admin only, optional ?role=Student|Moderator|Admin)
    // ✅ Wrapped in { data: users }
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { role } = req.query;
        const query = role ? { role } : {};
        const users = await usersCollection.find(query).toArray();
        res.send({ data: users });
      } catch (error) {
        console.error("Failed to fetch users:", error);
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    // Get my user info
    app.get("/users/me", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const user = await usersCollection.findOne({ email });
        res.send(user);
      } catch (error) {
        console.error("Failed to fetch current user:", error);
        res.status(500).send({ message: "Failed to fetch user" });
      }
    });

    // Get role by email (for useRole hook)
    app.get("/users/role/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        if (email !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden" });
        }
        const user = await usersCollection.findOne({ email });
        res.send({ role: user?.role || "Student" });
      } catch (error) {
        console.error("Failed to fetch role:", error);
        res.status(500).send({ message: "Failed to fetch role" });
      }
    });

    // Update user role (Admin) - PATCH /users/:id/role
    app.patch("/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { role } = req.body; // 'Admin' | 'Moderator' | 'Student'

        if (!["Admin", "Moderator", "Student"].includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }

        const query = { _id: new ObjectId(id) };
        const updateDoc = { $set: { role } };

        const result = await usersCollection.updateOne(query, updateDoc);

        if (result.modifiedCount === 1) {
          res.send({ success: true, message: "User role updated successfully" });
        } else {
          res
            .status(404)
            .send({ message: "User not found or role unchanged" });
        }
      } catch (error) {
        console.error("Failed to update user role:", error);
        res.status(500).send({ message: "Failed to update user role" });
      }
    });

    // Delete user (Admin)
    app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };

        const result = await usersCollection.deleteOne(query);

        if (result.deletedCount === 1) {
          res.send({ success: true, message: "User deleted successfully" });
        } else {
          res.status(404).send({ message: "User not found" });
        }
      } catch (error) {
        console.error("Failed to delete user:", error);
        res.status(500).send({ message: "Failed to delete user" });
      }
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
        console.error("Error fetching scholarships:", err);
        res.status(500).send({ message: "Error fetching scholarships" });
      }
    });

    // Top scholarships (for Home page)
    app.get("/scholarships/top", async (req, res) => {
      try {
        const data = await scholarshipsCollection
          .find({})
          .sort({ applicationFees: 1, scholarshipPostDate: -1 })
          .limit(6)
          .toArray();
        res.send(data);
      } catch (error) {
        console.error("Error fetching top scholarships:", error);
        res.status(500).send({ message: "Error fetching top scholarships" });
      }
    });

    // Get scholarship by ID
    app.get("/scholarships/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const result = await scholarshipsCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        console.error("Error fetching scholarship by id:", error);
        res.status(500).send({ message: "Error fetching scholarship" });
      }
    });

    // Add scholarship (Admin)
    app.post("/scholarships", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const scholarship = req.body;
        const result = await scholarshipsCollection.insertOne(scholarship);
        res.send(result);
      } catch (error) {
        console.error("Error adding scholarship:", error);
        res.status(500).send({ message: "Error adding scholarship" });
      }
    });

    // Update scholarship (Admin)
    app.patch(
      "/scholarships/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const update = req.body;
          const result = await scholarshipsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: update }
          );
          res.send(result);
        } catch (error) {
          console.error("Error updating scholarship:", error);
          res.status(500).send({ message: "Error updating scholarship" });
        }
      }
    );

    // Delete scholarship (Admin)
    app.delete(
      "/scholarships/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const result = await scholarshipsCollection.deleteOne({
            _id: new ObjectId(id),
          });
          res.send(result);
        } catch (error) {
          console.error("Error deleting scholarship:", error);
          res.status(500).send({ message: "Error deleting scholarship" });
        }
      }
    );

    // =====================================================
    //  APPLICATIONS (Student + Moderator/Admin)
    // =====================================================

    // Create application (called after payment success/fail)
    app.post("/applications", verifyJWT, async (req, res) => {
      try {
        const application = req.body;
        application.applicationDate = application.applicationDate || new Date();
        application.applicationStatus =
          application.applicationStatus || "pending";
        application.paymentStatus = application.paymentStatus || "unpaid";

        const result = await applicationsCollection.insertOne(application);
        res.send(result);
      } catch (error) {
        console.error("Error creating application:", error);
        res.status(500).send({ message: "Error creating application" });
      }
    });

    // Get my applications (Student)
    app.get("/applications/me", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const result = await applicationsCollection
          .find({ userEmail: email })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching my applications:", error);
        res.status(500).send({ message: "Error fetching applications" });
      }
    });

    // Get all applications (Moderator OR Admin)
    // ✅ changed: role check inside, response wrapped { data: result }
    app.get("/applications", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const user = await usersCollection.findOne({ email });

        if (user?.role !== "Moderator" && user?.role !== "Admin") {
          return res.status(403).send({ message: "Forbidden" });
        }

        const result = await applicationsCollection.find().toArray();
        res.send({ data: result });
      } catch (error) {
        console.error("Error fetching applications:", error);
        res.status(500).send({ message: "Error fetching applications" });
      }
    });

    // Update application status / feedback (Moderator OR Admin)
    // ✅ changed: uses { status, feedback }, validates, stores as applicationStatus
    app.patch("/applications/:id/status", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const user = await usersCollection.findOne({ email });

        if (user?.role !== "Moderator" && user?.role !== "Admin") {
          return res.status(403).send({ message: "Forbidden" });
        }

        const id = req.params.id;
        const { status, feedback } = req.body;

        const validStatuses = ["Pending", "Processing", "Completed", "Rejected"];
        if (!validStatuses.includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const updateDoc = {
          applicationStatus: status,
          lastUpdated: new Date().toISOString(),
        };

        if (feedback !== undefined) {
          updateDoc.feedback = feedback;
        }

        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );

        if (result.modifiedCount === 1) {
          res.send({
            success: true,
            message: "Application status updated successfully",
          });
        } else {
          res.status(404).send({ message: "Application not found" });
        }
      } catch (error) {
        console.error("Error updating application status:", error);
        res
          .status(500)
          .send({ message: "Error updating application status" });
      }
    });

    // Update payment status (Student retry payment)
    app.patch("/applications/:id/payment", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const { paymentStatus } = req.body; // 'paid' | 'unpaid'
        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { paymentStatus } }
        );
        res.send(result);
      } catch (error) {
        console.error("Error updating payment status:", error);
        res.status(500).send({ message: "Error updating payment status" });
      }
    });

    // Delete application (Student)
    app.delete("/applications/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await applicationsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        console.error("Error deleting application:", error);
        res.status(500).send({ message: "Error deleting application" });
      }
    });

    // Get single application by id
    app.get("/applications/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        console.error("Error fetching application by id:", error);
        res.status(500).send({ message: "Error fetching application" });
      }
    });

    // =====================================================
    //  REVIEWS (Student + Moderator)
    // =====================================================

    // Add review
    app.post("/reviews", verifyJWT, async (req, res) => {
      try {
        const review = req.body;
        review.reviewDate = review.reviewDate || new Date();
        const result = await reviewsCollection.insertOne(review);
        res.send(result);
      } catch (error) {
        console.error("Error adding review:", error);
        res.status(500).send({ message: "Error adding review" });
      }
    });

    // Get reviews for a scholarship or by user
    app.get("/reviews", async (req, res) => {
      try {
        const { scholarshipId, userEmail } = req.query;
        const query = {};
        if (scholarshipId) query.scholarshipId = scholarshipId;
        if (userEmail) query.userEmail = userEmail;
        const result = await reviewsCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching reviews:", error);
        res.status(500).send({ message: "Error fetching reviews" });
      }
    });

    // Get my reviews (Student)
    app.get("/reviews/me", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const result = await reviewsCollection
          .find({ userEmail: email })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching my reviews:", error);
        res.status(500).send({ message: "Error fetching reviews" });
      }
    });

    // Update review (Student)
    app.patch("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const { ratingPoint, reviewComment } = req.body;
        const result = await reviewsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { ratingPoint, reviewComment } }
        );
        res.send(result);
      } catch (error) {
        console.error("Error updating review:", error);
        res.status(500).send({ message: "Error updating review" });
      }
    });

    // Delete review (Student or Moderator)
    app.delete("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await reviewsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        console.error("Error deleting review:", error);
        res.status(500).send({ message: "Error deleting review" });
      }
    });

    // Moderator: get all reviews
    app.get(
      "/moderator/reviews",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        try {
          const result = await reviewsCollection.find().toArray();
          res.send(result);
        } catch (error) {
          console.error("Error fetching all reviews (moderator):", error);
          res.status(500).send({ message: "Error fetching reviews" });
        }
      }
    );

    // =====================================================
    //  PAYMENTS (Stripe)
    // =====================================================

    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      try {
        const { applicationFees, serviceCharge } = req.body;

        const total =
          (Number(applicationFees) || 0) + (Number(serviceCharge) || 0);
        const amount = Math.round(total * 100); // Stripe works in cents

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
      } catch (error) {
        console.error("Error creating payment intent:", error);
        res.status(500).send({ message: "Error creating payment intent" });
      }
    });

    // =====================================================
    //  ANALYTICS (Admin)
    // =====================================================

    // New required /analytics endpoint (for dashboard)
    app.get("/analytics", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();
        const totalScholarships = await scholarshipsCollection.countDocuments();
        const totalApplications = await applicationsCollection.countDocuments();

        // Total revenue from paid applications
        const paidApplications = await applicationsCollection
          .find({ paymentStatus: "paid" })
          .toArray();

        const totalRevenue = paidApplications.reduce(
          (sum, app) => sum + (app.applicationFees || 0),
          0
        );

        // Top scholarships by application count
        const topScholarships = await applicationsCollection
          .aggregate([
            {
              $group: {
                _id: "$scholarshipId",
                applications: { $sum: 1 },
                name: { $first: "$scholarshipName" },
                university: { $first: "$universityName" },
              },
            },
            { $sort: { applications: -1 } },
            { $limit: 5 },
          ])
          .toArray();

        // Recent applications
const recentApplicationsRaw = await applicationsCollection
  .find({})
  .sort({ applicationDate: -1 })
  .limit(5)
  .project({
    userName: 1,
    userEmail: 1,
    universityName: 1,
    scholarshipName: 1,      
    applicationStatus: 1,
    applicationDate: 1,
  })
  .toArray();

const recentApplications = recentApplicationsRaw.map((app) => ({
  // what frontend expects
  applicantName: app.userName || app.userEmail || "Unknown user",
  scholarshipName:
    app.scholarshipName || app.universityName || "Unknown scholarship",
  status: app.applicationStatus,
  date: app.applicationDate,
}));


        // Users by role
        const usersByRole = {
          students: await usersCollection.countDocuments({ role: "Student" }),
          moderators: await usersCollection.countDocuments({
            role: "Moderator",
          }),
          admins: await usersCollection.countDocuments({ role: "Admin" }),
        };

        res.send({
          data: {
            totalUsers,
            totalScholarships,
            totalApplications,
            totalRevenue,
            topScholarships,
            recentApplications,
            usersByRole,
          },
        });
      } catch (error) {
        console.error("Failed to fetch analytics:", error);
        res.status(500).send({ message: "Failed to fetch analytics" });
      }
    });

    // Your old /analytics/overview (still fine to keep, not required but harmless)
    app.get("/analytics/overview", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await usersCollection.estimatedDocumentCount();
        const totalScholarships =
          await scholarshipsCollection.estimatedDocumentCount();
        const totalApplications =
          await applicationsCollection.estimatedDocumentCount();

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
      } catch (error) {
        console.error("Error fetching analytics overview:", error);
        res.status(500).send({ message: "Error fetching analytics overview" });
      }
    });
  } catch (error) {
    console.error("Mongo Connection Error:", error);
  }
}

run().catch(console.dir);

// Start Server

app.listen(port, () => {
  console.log(`🚀 ScholarStream server listening on port ${port}`);
});
