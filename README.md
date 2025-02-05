# Chatty - Realtime Chat Application  

Chatty is a realtime chat application built using modern web technologies. It allows users to send messages, share images, switch themes, and update their profiles. The application ensures seamless and secure user interactions.  

### 🚀 Live Demo  
The application is live and accessible at: [Chatty on Render](https://chatty-5bn9.onrender.com/)  

---

## Features  
- **Realtime Messaging:** Send and receive messages instantly with Socket.IO.  
- **Media Sharing:** Upload and share images seamlessly via Cloudinary.  
- **User Authentication:** Secure signup and login functionality with JWT and bcrypt.  
- **Profile Management:** Update user profile information effortlessly.  
- **Theme Customization:** Switch between themes to personalize the user experience.  

---

## Tech Stack  

### Frontend  
- ReactJS  
- TailwindCSS  
- DaisyUI  

### Backend  
- Node.js  
- Express.js  

### Database  
- MongoDB  

### Realtime Communication  
- Socket.IO  

### Media Management  
- Cloudinary  

---

## Getting Started  

Follow these steps to run the project locally.  

### Prerequisites  
- Node.js (v16 or later)  
- MongoDB (local or cloud-based, e.g., MongoDB Atlas)  
- Cloudinary account for media management  

### Installation  

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/ngvanloi/Chatty.git
   cd Chatty
   ```  

2. **Install Dependencies**  
   ```bash
   npm install
   ```  

3. **Set up Environment Variables**  
   Create a `.env` file in the root directory and add the following variables:  
   ```env
    MONGODB_URI=mongodb+srv://nguyenloisite:JOyAH2CYJlWecodw@cluster0.igq9g.mongodb.net/chat_db?retryWrites=true&w=majority&appName=Cluster0
    PORT=5001
    JWT_SECRET=mysecretkey
    NODE_ENV=development
    CLOUDINARY_CLOUD_NAME=dvojurzwg
    CLOUDINARY_API_KEY=278265484267171
    CLOUDINARY_API_SECRET=oM7C8-nl7bMu2RU-OWPr9hz70bo
   ```  

4. **Start the Server**  
   ```bash
   npm start
   ```  

5. **Access the Application**  
   Open your browser and navigate to `http://localhost:5000`.  

---

## Deployment  

Chatty is currently deployed on [Render](https://render.com/). Follow Render’s documentation to set up deployment if needed.  

---

## Contributions  
Contributions are welcome! Feel free to fork this repository, make changes, and submit a pull request.  

---

## License  
This project is licensed under the MIT License.  

---

## Contact  
For any questions or issues, feel free to reach out at [nguyenloi.site@gmail.com](mailto:nguyenloi.site@gmail.com).  
```