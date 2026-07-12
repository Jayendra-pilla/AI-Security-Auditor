# AI Security Auditor Backend

This folder contains the backend code for the application, built with FastAPI and PostgreSQL.

## Docker Deployment (Production Ready)

The application is dockerized and orchestrated using `docker-compose`.

### Environment Variables
Before running the application, ensure you have an `.env` file in the `backend/` directory.

Example `.env` content:
```env
# Database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=ai_security_auditor
POSTGRES_SERVER=db
POSTGRES_PORT=5432

# FastAPI App Config
JWT_SECRET_KEY=generate_a_strong_secret_key
CORS_ORIGINS=["http://localhost:3000"]

# Gemini AI configuration
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
```

### Docker Compose Commands

**Run the backend and PostgreSQL database (detached mode):**
```bash
docker-compose up -d
```
Docker Compose will build the image, start PostgreSQL, wait for it to become healthy, and then start the FastAPI web service.

**Stopping Containers:**
```bash
docker-compose down
```

**Removing Volumes (Warning: deletes database data!):**
```bash
docker-compose down -v
```

**Docker Build (Rebuilding after changes):**
```bash
docker-compose build
```

## Local Development (Without Docker)

1. Create a virtual environment and install dependencies:
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the application locally:
```bash
uvicorn app.main:app --reload
```
