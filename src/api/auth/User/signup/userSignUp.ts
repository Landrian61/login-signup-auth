import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import zxcvbn from "zxcvbn";
import { Resend } from "resend";
import prisma from "../../../../prisma/client";

const router = Router();

const resend = new Resend(process.env.RESEND_API_KEY);

// password strength validation function
const validatePasswordStrength = (password: string) => {
  const minLength = 8;
  const result = zxcvbn(password);
  return password.length >= minLength && result.score >= 3;
};

//get all user from the database
router.get("/users", async (req, res) => {
  try {
    const user = await prisma.user.findMany();
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// add user to the database
router.post("/user/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // validate password strength
  if (!validatePasswordStrength(password)) {
    return res.status(400).json({
      error: "Password is too weak. It should be at least 8 characters long!",
    });
  }

  const hashedPassword = await bcryptjs.hash(password, 10);

  // check if user already exists
  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (user) {
      return res.status(400).json({ error: "User already exists" });
    }

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    // create token data with timestamp
    const tokenData = {
      id: newUser.id,
      email: newUser.email,
      username: newUser.name,
      createdAt: new Date().toISOString(),
    };

    // create token
    const token = jwt.sign(tokenData, process.env.JWT_SECRET!, {
      expiresIn: "1h",
    });
    console.log("Token: ", token);
    // print out token expiry date
    console.log("Token expires : ", new Date(Date.now() + 3600000));

    // store the token in the database
    try {
      await prisma.user.update({
        where: { id: newUser.id },
        data: {
          verificationToken: token,
        },
      });
    } catch (error) {
      console.error("Error updating user token:", error);
      return res.status(400).json(error);
    }
    await prisma.user.update({
      where: { id: newUser.id },
      data: {
        verificationToken: token,
      },
    });

    //send verification email
    try {
      await resend.emails.send({
        from: "onboarding@resend.dev",
        to: newUser.email,
        subject: "Account Verification",
        html: `
      <h1>Welcome to NOVA CRM!</h1>
      <p>Thank you for signing up, ${newUser.name}. We're excited to have you on board.</p>
      <p>To get started, please verify your email address by clicking the button below:</p>
      <div style="text-align: center;">
        <a href="http://localhost:4000/auth/api_user/user/verify-email?token=${token}" 
           style="display: inline-block; padding: 10px 20px; font-size: 16px; color: white; background-color: blue; text-decoration: none; border-radius: 5px;">
           Verify Your Account
        </a>
      </div>
      <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
      <p>http://localhost:4000/auth/api_user/user/verify-email?token=${token}</p>
      <p>Best regards,<br>The Team</p>
    `,
      });

      res.status(201).send({
        message: "Account created successfully, please verify your email.",
      });
    } catch (error) {
      console.error("Error sending email:", error);
      return res.status(400).json(error);
    }
  } catch (error) {
    console.error("Error creating user account");
    res.status(400).send({ message: "Error creating user's account" });
  }
});

// verify user email
router.get("/user/verify-email", async (req, res) => {
  const token = req.query.token as string;

  console.log(token);

  if (!token) {
    return res.status(400).json({ error: "Invalid token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      id: string;
      email: string;
      username: string;
      createdAt: string;
    };

    // check if a token exists in the database
    const checkUser = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { verificationToken: true },
    });

    // check if both tokens match
    if (checkUser?.verificationToken !== token) {
      return res.status(400).json({ error: "Invalid token" });
    }

    // check if token has expired
    const tokenAge = Date.now() - new Date(decoded.createdAt).getTime();
    console.log(tokenAge);

    if (tokenAge > 3600000) {
      return res.status(400).json({ error: "Token has expired" });
    }

    const user = await prisma.user.update({
      where: { id: decoded.id },
      data: {
        isVerified: true,
        verificationToken: null,
      },
    });

    res.status(200).json({ message: "User verified successfully", user });
  } catch (error) {
    console.error("Error verifying user accoun: ", error);
    res.status(400).send({ message: "Error verifying user account" });
  }
});

//re-verify user in case of email verification failure
router.post("/user/reverify", async (req, res) => {
  const { email } = req.body;

  // Check if user exists
  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: "User is already verified" });
    }

    // Create token data
    const tokenData = {
      id: user.id,
      email: user.email,
      username: user.name,
      createdAt: new Date().toISOString(),
    };

    // Create token
    const token = jwt.sign(tokenData, process.env.JWT_SECRET!, {
      expiresIn: "1h",
    });

    // update the token in the database
    await prisma.user.update({
      where: { id: user.id },
      data: {
        verificationToken: token,
      },
    });

    console.log("Token: ", token);

    // Send verification email
    try {
      await resend.emails.send({
        from: "onboarding@resend.dev",
        to: user.email,
        subject: "Account Verification",
        html: `
      <h1>Welcome to NOVA CRM!</h1>
      <p>Thank you for signing up, ${user.name}. We're excited to have you on board.</p>
      <p>To get started, please verify your email address by clicking the button below:</p>
      <div style="text-align: center;">
        <a href="http://localhost:4000/auth/api_user/user/verify-email?token=${token}" 
           style="display: inline-block; padding: 10px 20px; font-size: 16px; color: white; background-color: blue; text-decoration: none; border-radius: 5px;">
           Verify Your Account
        </a>
      </div>
      <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
      <p>http://localhost:4000/auth/api_user/user/verify-email?token=${token}</p>
      <p>Best regards,<br>The Team</p>
    `,
      });
      res.status(200).send({
        message: "Verification email has been resent.",
      });
    } catch (error) {
      console.error("Error sending email:", error);
      return res.status(400).json(error);
    }
  } catch (error) {
    console.error("Error re-verifying user account:", error);
    res.status(400).send({ message: "Error re-verifying user's account" });
  }
});

export default router;
