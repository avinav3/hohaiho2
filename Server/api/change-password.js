// api/change-password.js
const express = require('express');
const bcrypt = require('bcrypt');
const Users = require('../models/Users');
const { authenticateAccessToken } = require('../middleware/auth');

const router = express.Router();

router.post('/change-password', authenticateAccessToken, async (req, res) => {
  const { opass, npass } = req.body;

  try {
    const user = await Users.findById(req.auth.id);

    if (!user) {
      return res.status(404).json({ flag: "0", message: "User not found." });
    }

    if (user && await bcrypt.compare(opass, user.password)) {
      const hashedPassword = await bcrypt.hash(npass, 10);
      user.password = hashedPassword;
      await user.save();

      return res.json({ flag: "1", message: "Password changed successfully." });
    } else {
      return res.json({ flag: "0", message: "Old password is incorrect." });
    }
  } catch (error) {
    console.error("Error changing password: ", error);
    return res.status(500).json({ flag: "0", message: "Database error" });
  }
});

module.exports = router;
