---
title: "Klara - AI Phishing Detector"
date: 2025-07-01
draft: false
tableOfContents: false
description: "AI-powered web application untuk mendeteksi dan mengidentifikasi phishing dalam pesan atau tautan menggunakan VirusTotal, Google Gemini, dan PhishTank API"
---

{{< figure src="klara.png" width="600" zoom="true">}}

## 🎯 Project Overview

**Klara** adalah aplikasi web berbasis AI yang dirancang untuk membantu pengguna internet mengidentifikasi dan menghindari ancaman phishing secara efektif. Nama "Klara" berasal dari kata "Clarity" yang mencerminkan misi inti aplikasi: membawa transparansi dan pemahaman yang jelas tentang keamanan URL.

---

### Problem Statement

Phishing merupakan salah satu ancaman keamanan siber yang paling umum dan berbahaya, dengan serangan yang semakin canggih setiap harinya. Pengguna membutuhkan alat verifikasi tautan yang:
- ✅ Informatif dan mudah dipahami
- ✅ Cepat dan akurat
- ✅ Menggunakan multiple security sources
- ✅ Memberikan penjelasan kontekstual

---

### Solution

Klara menggabungkan kekuatan dari tiga sumber analisis keamanan:
1. **VirusTotal** - Database dari 60+ security vendors
2. **Google Gemini AI** - Analisis kontekstual dengan penjelasan natural language
3. **PhishTank** - Community-driven phishing database (coming soon)

---

## ✨ Key Features

### 🔍 Multi-Source Security Analysis
Mengintegrasikan multiple APIs untuk memberikan analisis yang comprehensive:
- Real-time URL scanning dengan VirusTotal
- AI-powered context analysis dengan Google Gemini
- Risk level classification (Safe, Low, Medium, High, Critical)

### 🎨 Modern User Interface
- **Responsive Design**: Optimal di semua devices (mobile, tablet, desktop)
- **Dark Mode**: Toggle tema untuk kenyamanan mata
- **Intuitive UX**: Loading states, error handling, dan feedback yang jelas
- **Visual Indicators**: Color-coded status badges untuk quick assessment

### 💾 Smart History Management
- Automatic saving di localStorage
- Quick recheck dari history
- Limit 5 URL terakhir untuk performance
- Clear history function

### 🛡️ Comprehensive Risk Assessment
- Malicious/Suspicious/Harmless counts dari VirusTotal
- AI explanation tentang specific phishing indicators
- Severity levels dengan icon indicators
- Detailed breakdown untuk transparency

---

## 🏗️ Technical Architecture

### Backend Architecture (FastAPI)
- **Async Operations**: Concurrent API calls untuk performance
- **Error Handling**: Comprehensive try-catch dengan informative messages
- **CORS Configuration**: Secure cross-origin requests
- **Environment Management**: Secure API key handling dengan python-dotenv
- **Type Safety**: Pydantic models untuk request/response validation

### Frontend Architecture (Next.js)
- **Component-Based**: Modular React components
- **State Management**: React Hooks (useState, useEffect)
- **Client-Side Storage**: localStorage untuk history persistence
- **API Integration**: Fetch API dengan error handling
- **Conditional Rendering**: Dynamic UI based on analysis results

### DevOps & Deployment
- **Containerization**: Docker untuk isolated environments
- **Multi-Container**: Docker Compose untuk orchestration
- **Volume Mapping**: Hot reload untuk development
- **Port Management**: Backend (8000), Frontend (3000)

---

## 💡 Technical Highlights

### 1. Async Parallel Processing
```python
# Backend melakukan concurrent API calls
async with httpx.AsyncClient() as client:
    vt_task = get_virustotal_report(client, url)
    gemini_task = get_gemini_analysis(url)
    results = await asyncio.gather(vt_task, gemini_task, return_exceptions=True)
```
**Impact**: Reduced analysis time hingga 50%

### 2. Smart Error Recovery
- Partial success handling (jika salah satu API fail, tetap tampilkan hasil yang berhasil)
- Informative error messages untuk user
- Fallback mechanisms untuk API failures

### 3. Prompt Engineering untuk Gemini AI
```python
prompt = """
Analyze the following URL for potential phishing and security risks...
Provide assessment in JSON format with explanation and severity level...
Focus on phishing indicators such as misleading domains, fake urgency, etc.
"""
```
**Impact**: Consistent structured responses untuk parsing dan display

### 4. Responsive Dark Mode Implementation
```javascript
// Toggle dengan localStorage persistence
const toggleDarkMode = () => {
    const newMode = !isDarkMode;
    setIsDarkMode(newMode);
    document.body.classList.toggle('dark-mode', newMode);
    localStorage.setItem('darkMode', newMode);
};
```
**Impact**: Better UX dengan user preference persistence

---

## 🎓 Learning Outcomes

### Technical Skills Acquired
1. **Full-Stack Development**
   - RESTful API design dan implementation
   - Frontend-backend integration
   - State management di React

2. **AI Integration**
   - Google Gemini API implementation
   - Prompt engineering untuk structured outputs
   - JSON parsing dan validation

3. **Security Best Practices**
   - Environment variable management
   - CORS configuration
   - API key security

4. **DevOps**
   - Docker containerization
   - Multi-container orchestration
   - Development vs Production configurations

5. **UI/UX Design**
   - Responsive design principles
   - Dark mode implementation
   - Loading states dan error handling
   - Accessibility considerations

### Soft Skills
- Team collaboration (5 members)
- Project planning dan execution
- Documentation writing
- Problem-solving under constraints

---

## 🚀 Future Enhancements

### Phase 1 (Short-term)
- [ ] PhishTank API integration
- [ ] Enhanced error messages
- [ ] Loading time optimization
- [ ] Unit tests implementation

### Phase 2 (Mid-term)
- [ ] User authentication system
- [ ] Database untuk persistent history
- [ ] Advanced filtering dan search
- [ ] Export reports (PDF/JSON)

### Phase 3 (Long-term)
- [ ] Browser extension (Chrome/Firefox)
- [ ] Email analysis feature
- [ ] Bulk URL scanning
- [ ] Multi-language support
- [ ] Rate limiting & caching

---

## 🎯 Business Impact

### Target Users
- Individual internet users
- Small businesses
- Educational institutions
- Cybersecurity awareness programs

### Value Proposition
- **Time-Saving**: Quick URL verification (5-7 seconds)
- **Accuracy**: Multi-source analysis untuk reduced false positives
- **Education**: AI explanations meningkatkan user awareness
- **Accessibility**: Free to use, modern interface

---

## 👥 Team & Contributions

**Project Team** (5 Members):
- Chen Wen Qi (2702210623)
- Jason Tanuwidjaja (2702215952)
- Jesslyn Theodora Laudette (2702243584)
- Kevin Diaz Pramono (2702229472)
- Maryuzo Vega (2702279376)

### My Contributions
- Backend API development (FastAPI)
- Frontend UI implementation (Next.js/React)
- VirusTotal & Gemini API integration
- Docker containerization setup
- Documentation & README creation

---

## 📸 Screenshots

### Main Interface (Dark Mode)
{{< figure src="showcase_0.jpg" width="300" zoom="true">}}
*Clean dan modern interface dengan URL input dan analysis button*

### Analysis Results
{{< figure src="showcase_1.jpg" width="300" zoom="true">}}
*Detailed results dari VirusTotal dan Gemini AI dengan status badges*

---

## 🏆 Achievements

- ✅ Successfully integrated 2+ external APIs
- ✅ Implemented AI-powered analysis
- ✅ Built responsive full-stack application
- ✅ Completed Docker containerization
- ✅ Created comprehensive documentation
- ✅ Team collaboration success