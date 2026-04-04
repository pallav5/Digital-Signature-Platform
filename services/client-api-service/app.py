from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://192.168.1.106:3000"])

# Mock client data - simulating external insurance provider API
PRODUCTS = [
    {
        "id": "LIFE_001",
        "name": "SecureLife Plus",
        "type": "Life Insurance",
        "base_premium": 125.00,
        "coverage": 500000,
        "description": "Comprehensive life insurance with critical illness cover",
        "features": ["Death benefit", "Critical illness", "Premium waiver"]
    },
    {
        "id": "LIFE_002", 
        "name": "Family Protector",
        "type": "Life Insurance",
        "base_premium": 200.00,
        "coverage": 1000000,
        "description": "High coverage family protection plan",
        "features": ["Death benefit", "Accidental death", "Children coverage"]
    },
    {
        "id": "HEALTH_001",
        "name": "HealthShield Basic",
        "type": "Health Insurance",
        "base_premium": 150.00,
        "coverage": 150000,
        "description": "Essential hospital and medical coverage",
        "features": ["Hospital cover", "Ambulance", "GP visits"]
    },
    {
        "id": "HEALTH_002",
        "name": "HealthShield Premium",
        "type": "Health Insurance", 
        "base_premium": 350.00,
        "coverage": 750000,
        "description": "Premium health coverage with extras",
        "features": ["Private hospital", "Dental", "Optical", "Physio"]
    },
    {
        "id": "CAR_001",
        "name": "DriveSafe Comprehensive",
        "type": "Car Insurance",
        "base_premium": 85.00,
        "coverage": 45000,
        "description": "Full comprehensive car insurance",
        "features": ["Collision damage", "Theft protection", "Roadside assistance"]
    },
    {
        "id": "CAR_002",
        "name": "DriveSafe Third Party",
        "type": "Car Insurance",
        "base_premium": 45.00,
        "coverage": 20000,
        "description": "Budget third party coverage",
        "features": ["Third party damage", "Fire and theft"]
    }
]

# Client company information
CLIENT_INFO = {
    "company_name": "Website On",
    "abn": "12 345 678 901",
    "website": "https://insurancepartners.com.au",
    "contact_email": "support@websiteon.com.au"
}

@app.route('/api/products', methods=['GET'])
def get_products():
    """Get all insurance products from client's system"""
    return jsonify({
        "status": "success",
        "data": PRODUCTS,
        "count": len(PRODUCTS),
        "client": CLIENT_INFO
    }), 200

@app.route('/api/products/<product_id>', methods=['GET'])
def get_product(product_id):
    """Get single product details"""
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if product:
        return jsonify({
            "status": "success",
            "data": product
        }), 200
    return jsonify({
        "status": "error",
        "message": "Product not found"
    }), 404

@app.route('/api/calculate-premium', methods=['POST'])
def calculate_premium():
    """Calculate premium based on product, age, and coverage years"""
    data = request.get_json()
    
    product_id = data.get('product_id')
    age = data.get('age', 30)
    coverage_years = data.get('coverage_years', 1)
    
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return jsonify({"status": "error", "message": "Product not found"}), 404
    
    # Age factor calculation
    if age < 25:
        age_factor = 0.8
    elif age < 35:
        age_factor = 1.0
    elif age < 50:
        age_factor = 1.3
    else:
        age_factor = 1.8
    
    calculated_premium = round(product['base_premium'] * age_factor * coverage_years, 2)
    
    return jsonify({
        "status": "success",
        "data": {
            "product_id": product_id,
            "product_name": product['name'],
            "policy_type": product['type'],
            "base_premium": product['base_premium'],
            "age_factor": age_factor,
            "coverage_years": coverage_years,
            "calculated_premium": calculated_premium,
            "coverage": product['coverage'],
            "features": product.get('features', []),  # ADD THIS LINE
            "description": product.get('description', '')  # ADD THIS LINE
        }
    }), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "client-api-service",
        "client": CLIENT_INFO["company_name"]
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)