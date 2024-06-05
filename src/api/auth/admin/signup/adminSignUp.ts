import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import zxcvbn from "zxcvbn";
import { Resend } from "resend";
import prisma from "../../../../prisma/client";
const router = Router();

const resend = new Resend("re_RSA9if9i_KtTLPVvJ8peFJgr1u9fMh6Be");

// password strength validation function
const validatePasswordStrength = (password: string) => {
  const minLength = 8;
  const result = zxcvbn(password);
  return password.length >= minLength && result.score >= 3;
};

//get all admin from the database
router.get("/admins", async (req, res) => {
  try {
    const admin = await prisma.admin.findMany();
    res.json(admin);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch admins" });
  }
});

// add admin to the database
router.post("/admin/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // validate password strength
  if (!validatePasswordStrength(password)) {
    return res.status(400).json({
      error: "Password is too weak. It should be at least 8 characters long!",
    });
  }

  const hashedPassword = await bcryptjs.hash(password, 10);

  // check if admin already exists
  try {
    const admin = await prisma.admin.findUnique({
      where: { email },
    });

    if (admin) {
      return res.status(400).json({ error: "Admin already exists" });
    }

    const newAdmin = await prisma.admin.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    // create token data with timestamp
    const tokenData = {
      id: newAdmin.id,
      email: newAdmin.email,
      username: newAdmin.name,
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
    await prisma.admin.update({
      where: { id: newAdmin.id },
      data: {
        verificationToken: token,
      },
    });

    //send verification email
    try {
      await resend.emails.send({
        from: "onboarding@resend.dev",
        to: newAdmin.email,
        subject: "Account Verification",
        html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h1 style="color: #2c3e50;">Welcome to NOVA CRM!</h1>
          <p>Thank you for signing up, ${newAdmin.name}. We're excited to have you on board.</p>
          <p>To get started, please verify your email address by clicking the button below:</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="http://localhost:3000/verifyEmail" 
               style="display: inline-block; padding: 10px 20px; font-size: 16px; color: white; background-color: teal; text-decoration: none; border-radius: 5px;">
               Verify Your Account
            </a>
          </div>
          <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
          <p style="word-break: break-all;">http://localhost:4000/auth/api_admin/admin/verify-email?token=${token}</p>
          <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
          <p>Best regards,<br>The Team</p>
          <footer style="margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; font-size: 12px; color: #999;">
            <p>This email was sent to ${newAdmin.email}. If you did not sign up for this account, please ignore this email.</p>
            <p style="margin-top: 10px;">NOVA CRM, 123 Business Rd, Business City, BC 12345</p>
          </footer>
        </div>
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
    console.error("Error creating admin account:", error);
    res.status(400).send({ message: "Error creating admin's account" });
  }
});

// verify admin email
router.get("/admin/verify-email", async (req, res) => {
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
    const checkAdmin = await prisma.admin.findUnique({
      where: { id: decoded.id },
      select: { verificationToken: true },
    });

    // check if both tokens match
    if (checkAdmin?.verificationToken !== token) {
      return res.status(400).json({ error: "Invalid token" });
    }

    // check if token has expired
    const tokenAge = Date.now() - new Date(decoded.createdAt).getTime();
    console.log(tokenAge);

    if (tokenAge > 3600000) {
      return res.status(400).json({ error: "Token has expired" });
    }

    const admin = await prisma.admin.update({
      where: { id: decoded.id },
      data: {
        isVerified: true,
        verificationToken: null,
      },
    });

    res.status(200).json({ message: "Admin verified successfully", admin });
  } catch (error) {
    console.error("Error verifying admin account: ", error);
    res.status(400).send({ message: "Error verifying admin account" });
  }
});

//re-verify admin in case of email verification failure
router.post("/admin/reverify", async (req, res) => {
  const { email } = req.body;

  // Check if admin exists
  try {
    const admin = await prisma.admin.findUnique({ where: { email } });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    if (admin.isVerified) {
      return res.status(400).json({ error: "Admin is already verified" });
    }

    // Create token data
    const tokenData = {
      id: admin.id,
      email: admin.email,
      username: admin.name,
      createdAt: new Date().toISOString(),
    };

    // Create token
    const token = jwt.sign(tokenData, process.env.JWT_SECRET!, {
      expiresIn: "1h",
    });

    // update the token in the database
    await prisma.admin.update({
      where: { id: admin.id },
      data: {
        verificationToken: token,
      },
    });

    console.log("Token: ", token);

    // Send verification email
    try {
      await resend.emails.send({
        from: "onboarding@resend.dev",
        to: admin.email,
        subject: "Account Verification",
        html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h1 style="color: #2c3e50;">Welcome to NOVA CRM!</h1>
        <p>Thank you for signing up, ${admin.name}. We're excited to have you on board.</p>
        <p>To get started, please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="http://localhost:4000/auth/api_admin/admin/verify-email?token=${token}" 
             style="display: inline-block; padding: 10px 20px; font-size: 16px; color: white; background-color: teal; text-decoration: none; border-radius: 5px;">
             Verify Your Account
          </a>
        </div>
        <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
        <p style="word-break: break-all;">http://localhost:4000/auth/api_admin/admin/verify-email?token=${token}</p>
        <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
        <p>Best regards,<br>The Team</p>
        <footer style="margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; font-size: 12px; color: #999;">
          <p>This email was sent to ${admin.email}. If you did not sign up for this account, please ignore this email.</p>
          <p style="margin-top: 10px;">NOVA CRM, 123 Business Rd, Business City, BC 12345</p>
        </footer>
      </div>
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
    console.error("Error re-verifying admin account:", error);
    res.status(400).send({ message: "Error re-verifying admin's account" });
  }
});

// Check verification status
router.get("/admin/check-verification", async (req, res) => {
  const email = req.query.email as string;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const admin = await prisma.admin.findUnique({
      where: { email },
      select: { isVerified: true },
    });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    res.json({ isVerified: admin.isVerified });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
