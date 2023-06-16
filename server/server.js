import express from 'express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import User from './models/User.js';
import { config } from 'dotenv';

config();

const app = express();

app.use(express.json());

// Database Connection
try {
  mongoose.connect(process.env.DATABASE_URI);
  console.log('MongoDB Connected Successfully!!!');
} catch (err) {
  console.error('Error: ', err);
}

app.get('/', (req, res) => {
  res.json({ msg: 'Working perfectly!!' });
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(401).json({ msg: 'User Already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name: name,
      email: email,
      password: hashedPassword,
    });
    await newUser.save();

    const token = jwt.sign(
      {
        userId: newUser._id,
        name: newUser.name,
        email: newUser.email,
        password: newUser.password,
      },
      process.env.JWT_SECRET
    );

    res
      .status(201)
      .json({ msg: 'User registered successfully', newUser, token: token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ msg: 'User not found!' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ msg: 'Password is incorrect!' });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        name: user.name,
        email: user.email,
        password: user.password,
      },
      process.env.JWT_SECRET
    );

    res
      .status(201)
      .json({ msg: 'User registered successfully', user, token: token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
