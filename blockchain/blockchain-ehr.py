from flask import Flask, request, jsonify, render_template
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse

MINING_SENDER = "EHR_System"
MINING_REWARD = 0  # No mining reward for healthcare system
MINING_DIFFICULTY = 2

class HealthBlockchain:
    def __init__(self):
        self.medical_records = []  # Current medical records pending to be added to chain
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.access_permissions = {}  # Dictionary to store patient-provider permissions
        # Create the genesis block
        self.create_block(0, '00')

    def register_node(self, node_url):
        """Add a new node to the list of nodes"""
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def create_block(self, nonce, previous_hash):
        """Add a block of medical records to the blockchain"""
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'medical_records': self.medical_records,
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        
        self.medical_records = []  # Reset pending records
        self.chain.append(block)
        return block

    def verify_record_signature(self, patient_public_key, signature, record):
        """Verify the signature of a medical record"""
        public_key = RSA.importKey(binascii.unhexlify(patient_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(record).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def valid_proof(records, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """Check if a nonce satisfies the mining difficulty requirements"""
        guess = (str(records) + str(last_hash) + str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        """Proof of work algorithm"""
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.medical_records, last_hash, nonce) is False:
            nonce += 1
        return nonce

    @staticmethod
    def hash(block):
        """Create a SHA-256 hash of a block"""
        # Ensure the dictionary is ordered to get consistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    def submit_medical_record(self, patient_public_key, provider_public_key, signature, record_data):
        """Submit a new medical record to the blockchain"""
        medical_record = OrderedDict({
            'patient_public_key': patient_public_key,
            'provider_public_key': provider_public_key,
            'timestamp': time(),
            'record_data': record_data,
            'record_type': record_data.get('type', 'general'),
            'access_level': record_data.get('access_level', 'private')
        })

        if self.verify_record_signature(patient_public_key, signature, medical_record):
            self.medical_records.append(medical_record)
            return len(self.chain) + 1
        return False

    def grant_access(self, patient_public_key, provider_public_key, access_level, signature):
        """Grant access to a healthcare provider"""
        if patient_public_key not in self.access_permissions:
            self.access_permissions[patient_public_key] = {}
        
        permission = {
            'provider_public_key': provider_public_key,
            'access_level': access_level,
            'timestamp': time()
        }
        
        if self.verify_record_signature(patient_public_key, signature, permission):
            self.access_permissions[patient_public_key][provider_public_key] = permission
            return True
        return False

    def verify_access(self, patient_public_key, provider_public_key, required_access_level):
        """Verify if a provider has appropriate access level"""
        if patient_public_key in self.access_permissions:
            if provider_public_key in self.access_permissions[patient_public_key]:
                permission = self.access_permissions[patient_public_key][provider_public_key]
                return self._check_access_level(permission['access_level'], required_access_level)
        return False

    def resolve_conflicts(self):
        """Consensus algorithm - resolve conflicts by replacing chain with longest valid chain"""
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True
        return False

    def valid_chain(self, chain):
        """Check if a blockchain is valid"""
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(
                block['medical_records'],
                block['previous_hash'],
                block['nonce'],
                MINING_DIFFICULTY
            ):
                return False

            last_block = block
            current_index += 1

        return True

    def _check_access_level(self, granted_level, required_level):
        """Check if granted access level meets required access level"""
        access_hierarchy = {
            'emergency': 3,
            'full': 2,
            'limited': 1,
            'none': 0
        }
        return access_hierarchy.get(granted_level, 0) >= access_hierarchy.get(required_level, 0)

    def get_patient_records(self, patient_public_key, requester_public_key):
        """Retrieve patient records based on access permissions"""
        if patient_public_key == requester_public_key:
            return self._get_all_patient_records(patient_public_key)
        
        if not self.verify_access(patient_public_key, requester_public_key, 'limited'):
            return []
        
        access_level = self.access_permissions[patient_public_key][requester_public_key]['access_level']
        return self._get_filtered_patient_records(patient_public_key, access_level)

    def _get_all_patient_records(self, patient_public_key):
        """Get all records for a patient"""
        return [record for block in self.chain 
                for record in block['medical_records'] 
                if record['patient_public_key'] == patient_public_key]

    def _get_filtered_patient_records(self, patient_public_key, access_level):
        """Get filtered records based on access level"""
        return [record for block in self.chain 
                for record in block['medical_records'] 
                if record['patient_public_key'] == patient_public_key 
                and self._check_access_level(access_level, record['access_level'])]

# Initialize Flask application
app = Flask(__name__)
CORS(app)
blockchain = HealthBlockchain()

@app.route('/')
def index():
    return render_template('./index.html')
'''
@app.route('/mine', methods=['GET'])
def mine():
    # Run the proof of work algorithm
    nonce = blockchain.proof_of_work()

    # Add the mining reward transaction (0 in this case)
    blockchain.submit_medical_record(
        sender_public_key=MINING_SENDER,
        provider_public_key=blockchain.node_id,
        signature='',
        record_data={'type': 'mining_reward', 'amount': MINING_REWARD}
    )
        
    # Create the new block
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New block mined',
        'block_number': block['block_number'],
        'medical_records': block['medical_records'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200
'''
@app.route('/mine', methods=['GET'])
def mine():
    try:
        if not blockchain.medical_records:
            return jsonify({'message': 'No records to mine'}), 400

        nonce = blockchain.proof_of_work()
        last_block = blockchain.chain[-1]
        previous_hash = blockchain.hash(last_block)
        block = blockchain.create_block(nonce, previous_hash)

        response = {
            'message': 'New block created',
            'block_number': block['block_number'],
            'transactions': block['medical_records'],
            'nonce': block['nonce'],
            'previous_hash': block['previous_hash'],
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e), 'message': 'Mining failed'}), 500

#error handler
@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': str(error), 'message': 'Internal server error'}), 500

@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes)
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200

@app.route('/medical_records/new', methods=['POST'])
def new_medical_record():
    values = request.form
    required = ['patient_public_key', 'provider_public_key', 'signature', 'record_data']
    
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create new medical record
    result = blockchain.submit_medical_record(
        values['patient_public_key'],
        values['provider_public_key'],
        values['signature'],
        json.loads(values['record_data'])
    )

    if result == False:
        response = {'message': 'Invalid record/signature'}
        return jsonify(response), 406
    else:
        response = {'message': f'Medical record will be added to Block {result}'}
        return jsonify(response), 201

@app.route('/access/grant', methods=['POST'])
def grant_provider_access():
    try:
        values = request.form
        required = ['patient_public_key', 'provider_public_key', 'access_level', 'signature']
        
        if not all(k in values for k in required):
            return jsonify({'error': 'Missing values'}), 400

        result = blockchain.grant_access(
            values['patient_public_key'],
            values['provider_public_key'],
            values['access_level'],
            values['signature']
        )
        
        if result:
            # Debug print to verify data
            print("Access granted:", {
                'patient': values['patient_public_key'],
                'provider': values['provider_public_key'],
                'level': values['access_level']
            })
            print("Current permissions:", blockchain.access_permissions)
            
            return jsonify({'message': 'Access granted successfully'}), 200
        else:
            return jsonify({'error': 'Invalid signature or request'}), 406
            
    except Exception as e:
        print("Grant access error:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/medical_records/get', methods=['GET'])
def get_medical_records():
    values = request.args
    required = ['patient_public_key', 'requester_public_key']
    
    if not all(k in values for k in required):
        return 'Missing values', 400

    records = blockchain.get_patient_records(
        values['patient_public_key'],
        values['requester_public_key']
    )

    response = {'medical_records': records}
    return jsonify(response), 200

# Add these imports to your Flask app
from Crypto.PublicKey import RSA
import binascii

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    """Generate a new key pair"""
    key = RSA.generate(2048)
    private_key = binascii.hexlify(key.exportKey('DER')).decode('utf-8')
    public_key = binascii.hexlify(key.publickey().exportKey('DER')).decode('utf-8')
    
    return jsonify({
        'private_key': private_key,
        'public_key': public_key
    }), 200

@app.route('/keygen')
def keygen():
    return render_template('keygen.html')

@app.route('/sign_data', methods=['POST'])
def sign_data():
    """Sign data with a private key"""
    try:
        data = request.json
        private_key = data['private_key']
        data_to_sign = data['data']
        
        # Convert data to OrderedDict for consistent hashing
        if isinstance(data_to_sign, dict):
            data_to_sign = OrderedDict(sorted(data_to_sign.items()))
        
        key = RSA.importKey(binascii.unhexlify(private_key))
        signer = PKCS1_v1_5.new(key)
        h = SHA.new(str(data_to_sign).encode('utf8'))
        signature = binascii.hexlify(signer.sign(h)).decode('utf8')
        
        print("Generated signature for:", data_to_sign)
        return jsonify({'signature': signature}), 200
        
    except Exception as e:
        print("Signing error:", str(e))
        return jsonify({'error': str(e)}), 400
    
@app.route('/view_records')
def view_records_page():
    return render_template('view_records.html')

@app.route('/pending_records', methods=['GET'])
def get_pending_records():
    """View all pending records that haven't been mined yet"""
    response = {
        'pending_records': blockchain.medical_records,
        'count': len(blockchain.medical_records)
    }
    return jsonify(response), 200
@app.route('/mining')
def mining_interface():
    return render_template('mining.html')

@app.route('/debug/access', methods=['GET'])
def debug_access():
    values = request.args
    patient_key = values.get('patient_public_key')
    provider_key = values.get('provider_public_key')
    
    access_info = {
        'has_permission': blockchain.verify_access(patient_key, provider_key, 'limited'),
        'all_permissions': blockchain.access_permissions,
        'patient_permissions': blockchain.access_permissions.get(patient_key, {}),
        'provider_specific': blockchain.access_permissions.get(patient_key, {}).get(provider_key, None)
    }
    return jsonify(access_info), 200
    
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)