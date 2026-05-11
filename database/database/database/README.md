# Database Documentation - Insurance Digital Signature Platform

## 📊 Schema Overview

Created by: **[Your Name]** (Database Lead)

### Tables Structure

| Table | Purpose |
|-------|---------|
| `users` | Store user information (customers, agents, admins) |
| `documents` | Store insurance document metadata |
| `signatures` | Store digital signature records |
| `audit_logs` | Track all platform activities for security |

## 🚀 Setup Instructions

### Local Development
1. **Start PostgreSQL:**
   ```bash
   docker run -d --name postgres-db -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:15
2. Connect to database:
bash
psql -h localhost -U postgres

3. Run the schema to create tables:
sql
\i database/schema.sql
4. Load sample data:
sql
\i database/seed.sql
5.Verify everything worked:

sql
SELECT * FROM users;
SELECT * FROM documents;
SELECT * FROM signatures;
text

