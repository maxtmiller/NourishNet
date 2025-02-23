# HackCanada: Food Donation Platform

## About Our Platform
Our platform is designed to bridge the gap between businesses and charitable organizations, making food donations seamless and rewarding. By leveraging modern technology, we ensure that surplus food reaches those in need efficiently.

## Our Mission
We believe in reducing food waste while helping communities. Our goal is to create a sustainable ecosystem where businesses can donate excess food and support local initiatives.

## Key Features
- **Seamless Donation Process:** Easily list and manage food donations with just a few clicks.
- **Government Incentives:** Get insights into tax benefits and financial incentives for food donations.
- **Real-Time Tracking:** Monitor the status of your donations and see their impact.
- **Secure Transactions:** Ensure that all data and interactions are encrypted and protected.
- **Community Engagement:** Connect with food banks, shelters, and organizations in your area.

## Technologies Used
- **Backend:** Flask (Python)
- **Frontend:** HTML, CSS
- **Database:** MongoDB (via pymongo)
- **APIs & Libraries:**
  - Flask-Session (for session management)
  - Requests (for making HTTP requests)
  - Pillow (for image processing)
  - Cohere (AI/ML integrations)
  - NumPy (for data processing)
  - Google Auth (for authentication)
  - OpenCage (for geolocation services)

## How to Run the Project
### Prerequisites
Ensure you have Python installed (preferably Python 3.11 or later). You also need to have `pip` installed.

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd HackCanada
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use 'venv\Scripts\activate'
3. Install dependencies:
   ```bash
   python -m ensurepip --upgrade
   python -m pip install -r requirements.txt
4. Run the Flask application:
   ```bash
   flask run
5. Open the application in your browser using the terminal local host link. You're all set!
