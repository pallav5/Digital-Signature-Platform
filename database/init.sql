-- ============================================================
-- Digital Signature Platform — Database Schema
-- ============================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INTEGER DEFAULT 0        -- ADDED: account lockout
);

-- Proposals table
CREATE TABLE IF NOT EXISTS proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    policy_type VARCHAR(100) NOT NULL,
    premium_amount DECIMAL(10,2),
    pdf_path VARCHAR(500),
    status VARCHAR(50) DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    features TEXT,                                  -- ADDED: product features
    product_description TEXT                        -- ADDED: product description
);

-- Signatures table
CREATE TABLE IF NOT EXISTS signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID REFERENCES proposals(id),
    user_id UUID REFERENCES users(id),
    signature_hash VARCHAR(500),
    kms_key_id VARCHAR(255),
    signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_valid BOOLEAN DEFAULT TRUE,
    document_hash VARCHAR(500),                     -- ADDED: tamper detection
    ip_address VARCHAR(50),                         -- ADDED: audit trail
    device_info TEXT,                               -- ADDED: signing certificate
    user_agent TEXT,                                -- ADDED: device tracking
    final_pdf_hash VARCHAR(500)                     -- ADDED: PDF tamper detection
);

-- Audit log table (immutable)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    device_info TEXT,
    risk_score DECIMAL(5,2) DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fraud events table
CREATE TABLE IF NOT EXISTS fraud_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(100),
    risk_score DECIMAL(5,2),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Safe Migration: adds missing columns to existing databases
-- Safe to run multiple times — checks before adding
-- ============================================================
DO $$
BEGIN
    -- users: failed_login_attempts
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='failed_login_attempts')
    THEN
        ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
        RAISE NOTICE 'Added failed_login_attempts to users';
    END IF;

    -- proposals: features
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='proposals' AND column_name='features')
    THEN
        ALTER TABLE proposals ADD COLUMN features TEXT;
        RAISE NOTICE 'Added features to proposals';
    END IF;

    -- proposals: product_description
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='proposals' AND column_name='product_description')
    THEN
        ALTER TABLE proposals ADD COLUMN product_description TEXT;
        RAISE NOTICE 'Added product_description to proposals';
    END IF;

    -- signatures: document_hash
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='signatures' AND column_name='document_hash')
    THEN
        ALTER TABLE signatures ADD COLUMN document_hash VARCHAR(500);
        RAISE NOTICE 'Added document_hash to signatures';
    END IF;

    -- signatures: ip_address
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='signatures' AND column_name='ip_address')
    THEN
        ALTER TABLE signatures ADD COLUMN ip_address VARCHAR(50);
        RAISE NOTICE 'Added ip_address to signatures';
    END IF;

    -- signatures: device_info
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='signatures' AND column_name='device_info')
    THEN
        ALTER TABLE signatures ADD COLUMN device_info TEXT;
        RAISE NOTICE 'Added device_info to signatures';
    END IF;

    -- signatures: user_agent
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='signatures' AND column_name='user_agent')
    THEN
        ALTER TABLE signatures ADD COLUMN user_agent TEXT;
        RAISE NOTICE 'Added user_agent to signatures';
    END IF;

    -- signatures: final_pdf_hash
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='signatures' AND column_name='final_pdf_hash')
    THEN
        ALTER TABLE signatures ADD COLUMN final_pdf_hash VARCHAR(500);
        RAISE NOTICE 'Added final_pdf_hash to signatures';
    END IF;

END $$;
