import { Router } from "express";
import bcryptjs from "bcryptjs";
import rateLimit from "express-rate-limit";
import session from "express-session";
import prisma from "../../../../prisma/client";
import { Session } from "express-session";

const router = Router();

// rate limiter middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests
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

interface UserSession extends Session {
  user: {
    id: number;
    name: string;
    email: string;
  };
}

//user login
router.post("/user/login", limiter, async (req, res) => {
  try {
    // Check if the user is already logged in
    if ((req.session as UserSession).user) {
      return res
        .status(200)
        .json({ message: "User already logged in", success: true });
    }

    const { email, password } = req.body;

    // check if user exists in the database
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(400).json({ error: "User does not exist" });
    } else {
      // compare password
      const isMatch = await bcryptjs.compare(password, user.password);

      console.log(req.session);
      if (!isMatch) {
        // increment login attempts

        return res.status(400).json({ error: "Invalid credentials" });
      } else {
        // start a session
        (req.session as UserSession).user = {
          id: user.id,
          name: user.name,
          email: user.email,
        };

        // store user in cookie
        res.cookie("user", user.id, {
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

router.get("/user/logout", async (req, res) => {
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
