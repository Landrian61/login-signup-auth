import { Router } from "express";
import bcryptjs from "bcryptjs";
import rateLimit from "express-rate-limit";
import session from "express-session";
import { Session } from "express-session";
import prisma from "../../../../prisma/client";

const router = Router();

// rate limiter middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 100 requests
  message: "Too many login attempts, please try again after 15 minutes",
});

router.use(limiter);

// session middleware
router.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

interface AdminSession extends Session {
  admin: {
    id: number;
    name: string;
    email: string;
  };
}

//admin login
router.post("/admin/login", limiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // check if admin exists in the database
    const admin = await prisma.admin.findUnique({
      where: {
        email,
      },
    });

    if (!admin) {
      return res.status(400).json({ error: "Admin does not exist" });
    } else {
      // compare password
      const isMatch = await bcryptjs.compare(password, admin.password);

      if (!isMatch) {
        // increment login attempts

        return res.status(400).json({ error: "Invalid credentials" });
      } else {
        // start a session
        (req.session as AdminSession).admin = {
          id: admin.id,
          name: admin.name,
          email: admin.email,
        };

        // store admin in cookie
        res.cookie("admin", admin.id, {
          maxAge: 24 * 60 * 60 * 1000,
          httpOnly: true,
          secure: true,
        });

        console.log(req.session);
        res.json({ message: "Login successful", success: true });
      }
    }
  } catch (error: any) {
    return res.status(400).json({ error: error.message });
  }
});

router.get("/admin/logout", async (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session");
      return res.status(400).json({ error: "Error destroying session" });
    }

    res.clearCookie("user");
    res.json({ message: "Logout successful" });
  });
});

export default router;
