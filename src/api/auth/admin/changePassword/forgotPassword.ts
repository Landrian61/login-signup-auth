import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { Resend } from "resend";
import jwt from "jsonwebtoken";
import prisma from "../../../../prisma/client";


const router = Router();
const resend = new Resend("re_RSA9if9i_KtTLPVvJ8peFJgr1u9fMh6Be");

// get a single admin from the database
router.get("/admin/:id", async (req, res) => {
  const { id } = req.params;

  console.log("Admin ID: ", id);

  try {
    const admin = await prisma.admin.findUnique({
      where: { id },
    });

    if (!admin) {
      return res.status(400).json({ error: "Admin does not exist" });
    }

    res.json(admin);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch admin" });
  }
});

router.post("/admin/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const admin = await prisma.admin.findUnique({
      where: { email },
    });

    if (!admin) {
      return res.status(400).json({ error: "Admin does not exist" });
    }

    // create token data with timestamp
    const tokenData = {
      id: admin.id,
      email: admin.email,
      username: admin.name,
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
      where: { id: admin.id },
      data: {
        forgotPasswordToken: token,
      },
    });

    // send email with password reset link
    try {
      await resend.emails.send({
        from: "onboarding@resend.dev",
        to: admin.email,
        subject: "Account Verification",
        html: `<h1>Click the link below to reset ypur password</h1>
        <a href="http://localhost:4000/api_admin/admin/reset-password/${admin.id}?token=${token}">Reset Password</a>`,
      });
    } catch (error) {
      console.error("Error sending email:", error);
      return res.status(400).json(error);
    }
  } catch (error) {}
});

export default router;
