Secure Full-Stack Authentication System with AI Features
This is a complete, production-ready authentication system built with the MERN stack (MongoDB, Express, React, Node.js) and enhanced with AI-powered productivity tools using the Gemini API. It provides a robust foundation for any modern web application requiring secure user management.

Key Features
JWT Authentication: Secure, stateless authentication using JSON Web Tokens with a refresh token rotation strategy for improved security and user experience.

Role-Based Access Control (RBAC): Protects routes and endpoints based on user roles (e.g., user vs. admin).

Multi-Factor Security:

Email Verification: New users must verify their email address before they can log in.

Secure Password Reset: A secure token-based flow for users who have forgotten their password.

AI-Powered Productivity: A "Productivity Boost" feature on the user dashboard that uses the Gemini API to generate actionable tasks and milestones from a project goal.

Modern Frontend: A responsive and visually appealing user interface built with React and styled with Tailwind CSS.

Robust Backend: A scalable backend built with Node.js and Express, connected to a MongoDB database for data persistence.

Tech Stack
Backend:

Node.js

Express

MongoDB with Mongoose

JSON Web Token (jsonwebtoken)

bcrypt.js for password hashing

Nodemailer for sending emails

Dotenv for environment variables

Google Generative AI (@google/generative-ai)

Frontend:

React

Axios for API requests

Tailwind CSS for styling

Sonner for notifications

Setup and Installation
To get this project running locally, you'll need to set up both the backend and the frontend.

Prerequisites
Node.js (v14 or higher)

npm

MongoDB (either a local instance or a free cluster on MongoDB Atlas)

A Gemini API Key

An SMTP service for sending emails (e.g., Mailtrap for development)

1. Backend Setup
# Navigate to the backend directory
cd backend

# Install dependencies
npm install

# Create the .env file and fill in your credentials (see .env.example)
# Add your MongoDB URI, JWT secrets, email credentials, and Gemini API key

# Seed the database with initial roles ('user' and 'admin')
node seed.js

# Start the development server
npm run dev

The backend server will be running on http://localhost:5000.

2. Frontend Setup
# From the root directory, navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm start

The frontend React app will be running on http://localhost:3000.

Environment Variables
You must create a .env file in the backend directory.

# /backend/.env

# MongoDB Connection String
MONGODB_URI=your_mongodb_connection_string

# Port for the server
PORT=5000

# JSON Web Token Secrets (use long, random strings)
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret

# Email SMTP Credentials (e.g., from Mailtrap)
EMAIL_HOST=your_email_host
EMAIL_PORT=your_email_port
EMAIL_USERNAME=your_email_username
EMAIL_PASSWORD=your_email_password

# Google Gemini API Key
GEMINI_API_KEY=your_gemini_api_key

Running the Project
Start the Backend: Navigate to the backend folder and run npm run dev.

Start the Frontend: In a new terminal, navigate to the frontend folder and run npm start.

Open your browser and go to http://localhost:3000.
