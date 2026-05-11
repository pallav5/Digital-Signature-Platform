-- Sample/Test Data for Insurance Digital Signature Platform
-- Created by: [Your Name]

-- =============================================
-- Insert sample users
-- =============================================
INSERT INTO users (email, full_name, phone_number, address) VALUES
('john.doe@example.com', 'John Doe', '+1234567890', '123 Main St, New York, NY 10001'),
('jane.smith@example.com', 'Jane Smith', '+1234567891', '456 Oak Ave, Los Angeles, CA 90001'),
('insurance.agent@insureco.com', 'Mike Agent', '+1234567892', '789 Business Park, Chicago, IL 60601');

-- =============================================
-- Insert sample documents
-- =============================================
INSERT INTO documents (user_id, document_name, document_path, file_hash, file_size, status) VALUES
(1, 'Life Insurance Policy - John Doe', '/documents/policy_JD001.pdf', 'a3f5c8d9e2b1f4a7c6e8d9f0a1b2c3d4', 245760, 'pending'),
(2, 'Home Insurance - Jane Smith', '/documents/home_JS002.pdf', 'b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0', 512000, 'pending'),
(1, 'Health Insurance Rider', '/documents/health_JD003.pdf', 'c5d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1', 128000, 'signed');

-- =============================================
-- Insert sample signatures
-- =============================================
INSERT INTO signatures (document_id, signed_by, signature_hash, ip_address, user_agent) VALUES
(3, 1, 'sig_hash_001_def456ghi789jkl', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(2, 2, 'sig_hash_002_abc123def456ghi', '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)');

-- =============================================
-- Insert sample audit logs
-- =============================================
INSERT INTO audit_logs (user_id, action, document_id, details) VALUES
(1, 'UPLOAD_DOCUMENT', 1, '{"filename": "Life Insurance Policy", "size": "2.4MB"}'),
(2, 'VIEW_DOCUMENT', 2, '{"timestamp": "2024-01-15T10:30:00"}'),
(1, 'SIGN_DOCUMENT', 3, '{"signature_method": "digital", "verification": "passed"}');

-- =============================================
-- Verification queries (run to check data)
-- =============================================
-- SELECT COUNT(*) FROM users;
-- SELECT COUNT(*) FROM documents;
-- SELECT COUNT(*) FROM signatures;
