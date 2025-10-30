---
title: "Projects"
draft: false
---

Here are my projects:
# CyberInsight
## 🎯 Overview

CyberInsight is a comprehensive cyber security education platform designed to provide accessible and engaging content about digital security. The platform features a modern, responsive interface where users can browse articles, bookmark favorites, participate in discussions, and learn about various cybersecurity topics including encryption, network security, social engineering, and more.

**Live Website:** [https://cyberinsight.vercel.app/](https://cyberinsight.vercel.app/)

---

## 👨‍💼 My Role

**Full-Stack Developer & Project Manager**

As the lead developer and project manager, I was responsible for:

- **Project Planning:** Defined project scope, technical requirements, and development roadmap
- **Architecture Design:** Designed the full-stack architecture using Next.js 14 with App Router pattern
- **Database Design:** Created MongoDB schema for users, articles, and comments with proper relationships
- **Authentication System:** Implemented secure JWT-based authentication with bcrypt password hashing
- **Frontend Development:** Built responsive UI components using React, TypeScript, and Tailwind CSS
- **Backend Development:** Developed RESTful API endpoints with Next.js API routes
- **Admin Dashboard:** Created comprehensive admin panel for content management with statistics
- **Deployment & DevOps:** Set up CI/CD pipeline with GitHub and Vercel for automated deployments

---

## 🛠️ Technologies Used

### **Frontend**
- **Next.js 14** - React framework with App Router for SSR and SSG
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first CSS framework for responsive design
- **React Markdown** - Markdown rendering with syntax highlighting
- **React Icons** - Comprehensive icon library

### **Backend**
- **Next.js API Routes** - Serverless API endpoints
- **Mongoose** - MongoDB ODM for data modeling
- **bcryptjs** - Secure password hashing
- **jsonwebtoken (JWT)** - Stateless authentication
- **Node.js** - JavaScript runtime

### **Database**
- **MongoDB Atlas** - Cloud-hosted NoSQL database
- **Mongoose Schema** - Data validation and relationships

### **Deployment & Tools**
- **Vercel** - Hosting platform with automatic deployments
- **GitHub** - Version control and CI/CD integration
- **MongoDB Compass** - Database management tool

---

## ✨ Key Features & Contributions

### **1. User Authentication System**
- Implemented secure registration and login with JWT tokens
- Password hashing using bcrypt with 10 salt rounds
- Role-based access control (user/admin)
- Token expiration and refresh mechanism
- Protected routes with middleware authentication

### **2. Content Management System**
- **Admin Dashboard** with real-time statistics:
  - Total articles count
  - Published vs draft articles
  - Total views tracking
  - Category distribution
- **CRUD Operations** for articles:
  - Create articles with markdown support
  - Edit existing content
  - Delete with confirmation
  - Publish/unpublish toggle
- **Rich Text Content:**
  - Markdown rendering with `react-markdown`
  - Code syntax highlighting
  - Responsive images with Next.js Image optimization

### **3. User Features**
- **Article Browsing:**
  - Category filtering (Encryption, Network Security, Social Engineering, etc.)
  - Search functionality
  - Responsive grid layout
- **Bookmark System:**
  - Save favorite articles
  - Dedicated bookmarks page
  - One-click remove bookmarks
- **Comment System:**
  - User discussions on articles
  - Real-time comment display
  - User profile integration
- **Profile Management:**
  - Update name and email
  - View bookmarks count
  - Role display

### **4. Responsive Design**
- Mobile-first approach with Tailwind breakpoints
- Adaptive layouts for mobile, tablet, and desktop
- Touch-friendly UI elements
- Optimized typography and spacing

### **5. Performance Optimization**
- Server-Side Rendering (SSR) for SEO
- Static Site Generation (SSG) for fast page loads
- MongoDB query optimization with lean() and indexes
- Image optimization with Next.js Image component
- Code splitting and lazy loading

---

## 📊 Technical Highlights

### **Database Architecture**
```javascript
// User Schema
{
  name: String,
  email: String (unique, indexed),
  password: String (hashed),
  role: "user" | "admin",
  bookmarks: [ObjectId] (references articles),
  createdAt: Date
}

// Article Schema
{
  title: String,
  slug: String (unique, indexed),
  content: String (markdown),
  excerpt: String,
  category: String,
  tags: [String],
  author: String,
  image: String,
  views: Number,
  published: Boolean,
  createdAt: Date
}