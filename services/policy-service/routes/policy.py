from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

policy_bp = Blueprint('policy', __name__)

# Simulated insurance products
PRODUCTS = [
    {
        'id': 'LIFE001',
        'name': 'Life Insurance Basic',
        'type': 'Life Insurance',
        'base_premium': 120.00,
        'coverage': 500000,
        'description': 'Basic life insurance coverage'
    },
    {
        'id': 'LIFE002',
        'name': 'Life Insurance Premium',
        'type': 'Life Insurance',
        'base_premium': 250.00,
        'coverage': 1000000,
        'description': 'Premium life insurance coverage'
    },
    {
        'id': 'HEALTH001',
        'name': 'Health Insurance Basic',
        'type': 'Health Insurance',
        'base_premium': 180.00,
        'coverage': 100000,
        'description': 'Basic health insurance coverage'
    },
    {
        'id': 'HEALTH002',
        'name': 'Health Insurance Premium',
        'type': 'Health Insurance',
        'base_premium': 320.00,
        'coverage': 500000,
        'description': 'Premium health insurance coverage'
    },
    {
        'id': 'CAR001',
        'name': 'Car Insurance Comprehensive',
        'type': 'Car Insurance',
        'base_premium': 95.00,
        'coverage': 50000,
        'description': 'Comprehensive car insurance'
    }
]

# ── Get all products ──────────────────────────────────────
@policy_bp.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    return jsonify(PRODUCTS), 200

# ── Get quote ─────────────────────────────────────────────
@policy_bp.route('/quote', methods=['POST'])
@jwt_required()
def get_quote():
    user_id = get_jwt_identity()
    data = request.get_json()

    product_id = data.get('product_id')
    age = data.get('age', 30)
    coverage_years = data.get('coverage_years', 1)

    product = next(
        (p for p in PRODUCTS if p['id'] == product_id), None
    )

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # Premium calculation
    age_factor = 1.0
    if age > 50:
        age_factor = 1.5
    elif age > 40:
        age_factor = 1.25
    elif age > 30:
        age_factor = 1.1

    calculated_premium = round(
        product['base_premium'] * age_factor * coverage_years, 2
    )

    return jsonify({
        'product_id': product_id,
        'product_name': product['name'],
        'policy_type': product['type'],
        'base_premium': product['base_premium'],
        'calculated_premium': calculated_premium,
        'coverage': product['coverage'],
        'age_factor': age_factor,
        'coverage_years': coverage_years,
        'user_id': user_id
    }), 200