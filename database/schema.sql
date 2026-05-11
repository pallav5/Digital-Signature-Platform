-- Insurance Digital Signature Platform
-- Complete Database Schema
-- Created by: [Your Name]

-- =============================================
-- TABLE: users
-- Stores all platform users
-- =============================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================
-- TABLE: documents
-- Stores document metadata
-- =============================================
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    document_name VARCHAR(255) NOT NULL,
    document_path VARCHAR(500) NOT NULL,
    file_hash VARCHAR(255) UNIQUE NOT NULL,
    file_size BIGINT,
    status VARCHAR(50) DEFAULT 'pending',
    signature_required BOOLEAN DEFAULT TRUE,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- =============================================
-- TABLE: signatures
-- Stores digital signatures
-- =============================================
CREATE TABLE IF NOT EXISTS signatures (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
    signed_by INTEGER REFERENCES users(id),
    signature_hash VARCHAR(255) NOT NULL,
    signature_data TEXT,
    ip_address INET,
    user_agent TEXT,
    signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================
-- TABLE: audit_logs
-- Tracks all activities for security
-- =============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    document_id INTEGER,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================
-- INDEXES (for performance optimization)
-- =============================================
CREATE INDEX idx_documents_user_id ON documents(user_id);
CREATE INDEX idx_documents_status ON documents(status);
CREATE INDEX idx_signatures_document_id ON signatures(document_id);
CREATE INDEX idx_signatures_signed_at ON signatures(signed_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- =============================================
-- CONSTRAINTS & VALIDATIONS
-- =============================================
ALTER TABLE documents 
ADD CONSTRAINT chk_document_status 
CHECK (status IN ('pending', 'signed', 'expired', 'rejected'));

-- =============================================
-- COMMENTS (for documentation)
-- =============================================
COMMENT ON TABLE users IS 'Platform users (customers, agents, admins)';
COMMENT ON TABLE documents IS 'Insurance documents requiring signatures';
COMMENT ON TABLE signatures IS 'Digital signature records';
COMMENT ON TABLE audit_logs IS 'Security and activity audit trail';
