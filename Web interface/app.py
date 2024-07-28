from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
from datetime import datetime
from flask_cors import CORS, cross_origin
import pandas as pd
import pickle
import numpy as np
import tensorflow as tf
import datetime as dt

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/d/Videos/anis/Back-End/firewall.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Firewall(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    nat_source_port = db.Column(db.Integer)
    nat_destination_port = db.Column(db.Integer)
    bytes = db.Column(db.Integer)
    bytes_sent = db.Column(db.Integer)
    bytes_received = db.Column(db.Integer)
    packets = db.Column(db.Integer)
    elapsed_time_sec = db.Column(db.Integer)
    pkts_sent = db.Column(db.Integer)
    pkts_received = db.Column(db.Integer)
    action = db.Column(db.String(50))
    timestamp = db.Column(db.TIMESTAMP, default=datetime.now)  

def insert_into_firewall(data, timestamp):
    new_packet = Firewall(
        source_port=int(data['"Source Port"']),
        destination_port=int(data['"Destination Port"']),
        nat_source_port=int(data['"NAT Source Port"']),
        nat_destination_port=int(data['"NAT Destination Port"']),
        bytes=int(data['Bytes']),
        bytes_sent=int(data['"Bytes Sent"']),
        bytes_received=int(data['"Bytes Received"']),
        packets=int(data['Packets']),
        elapsed_time_sec=int(data['"Elapsed Time (sec)"']),
        pkts_sent=int(data['pkts_sent']),
        pkts_received=int(data['pkts_received']),
        action=data['action'],
        timestamp=timestamp
    )
    db.session.add(new_packet)
    db.session.commit()

@app.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=data['password'], admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    data = request.get_json()
    if not data or not data['name'] or not data['password']:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=data['name']).first()

    if not user or user.password != data['password']:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    token = jwt.encode({'public_id': user.public_id, 'exp': dt.datetime.utcnow() + dt.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token})
processing = False  # Variable de contrôle pour suivre l'état de l'exécution

@app.route('/execute', methods=['POST'])
def execute_code():
    global processing
    if processing:
        return jsonify({'message': 'Le traitement est déjà en cours.'}), 400
    
    processing = True  # Définir la variable de contrôle sur True (en cours d'exécution)
    try:
        data = pd.read_csv("AI\Dataset.csv")
        columnsdrop=['"Source Port"','Bytes','Packets']
        if 'Unnamed: 0' in data.columns:
            data.drop(['Unnamed: 0'],axis=1,inplace=True)

        df=data.copy()
        df=df.drop(columns=columnsdrop,axis=1)
        dfgan=df.copy()

        with open('AI\dstportdict.pkl', 'rb') as f:
            dstportdict = pickle.load(f)
        with open('AI\dnatsrcportdict.pkl', 'rb') as f:
            natsrcportdict = pickle.load(f)
        with open('AI\dnatdstportdict.pkl', 'rb') as f:
            natdstportdict = pickle.load(f)

        with open('AI\countfrequencyencoderGAN.pkl', 'rb') as f:
            countfreqGAN = pickle.load(f)

        with open('AI\standardscalerGAN.pkl','rb') as f:
            scaler=pickle.load(f)

        num=['"Bytes Sent"','"Bytes Received"','"Elapsed Time (sec)"', "pkts_sent","pkts_received"]
        num2=['"Destination Port"','"NAT Source Port"', '"NAT Destination Port"','"Bytes Sent"','"Bytes Received"','"Elapsed Time (sec)"',
                        "pkts_sent","pkts_received"]

        allow_model = tf.keras.models.load_model("AI\dallow_detection.h5")

        with open('AI\Random_forest.pkl', 'rb') as f:
            RF = pickle.load(f)

        with open('AI\scclass.pkl','rb') as f:
            scalerclass=pickle.load(f)

        data['action'] = 'unknown'

        for i in range(len(df)):
            timestamp = datetime.now()  # Générer le timestamp actuel
            dfgan_i = dfgan.iloc[i:i+1].copy()
            dfgan_i['"Destination Port"']=dfgan_i['"Destination Port"'].map(dstportdict)
            dfgan_i['"NAT Source Port"']=dfgan_i['"NAT Source Port"'].map(natsrcportdict)
            dfgan_i['"NAT Destination Port"']=dfgan_i['"NAT Destination Port"'].map(natdstportdict)
            dfgan_i = countfreqGAN.transform(dfgan_i)
            dfgan_i[num]=scaler.transform(dfgan_i[num])
            dfsansNan_i = dfgan_i[~dfgan_i.isin([np.nan, np.inf, -np.inf]).any(axis=1)]
            if dfsansNan_i.empty:
                allow_mask_i = True  
            else:
                allow_probs_i = allow_model.predict(dfsansNan_i)
                rmse_i = np.sqrt(np.sum((dfsansNan_i - allow_probs_i)**2, axis=1) / dfsansNan_i.shape[1])
                allow_mask_i = rmse_i > 0.08502309105681057
                allow_mask_i=allow_mask_i.bool()
            if not allow_mask_i:
                data.loc[i, 'action'] = 'allow'
            else:
                df_i = df.loc[i:i+1].copy()
                df_i[num2] = scalerclass.transform(df_i[num2])
                prediction_i = RF.predict(df_i)
                if prediction_i[0] == 0:
                    data.loc[i, 'action'] = 'deny'
                elif prediction_i[0] == 1:
                    data.loc[i, 'action'] = 'drop'
                elif prediction_i[0] == 2:
                    data.loc[i, 'action'] = 'reset-both'
            # Insérer le paquet dans la base de données avec le timestamp
            insert_into_firewall(data.iloc[i], timestamp)
        return jsonify({'message' : 'Code executed and result inserted into database!'})
    except Exception as e:
        print(e)
        return jsonify({'message': 'Une erreur s\'est produite lors de l\'exécution du code.'}), 500
    finally:
        processing = False  # Réinitialiser la variable de contrôle sur False (arrêter l'exécution)

@app.route('/pause', methods=['POST'])
def pause_execution():
    global processing
    if not processing:
        return jsonify({'message': 'Aucun traitement en cours à mettre en pause.'}), 400
    
    processing = False  # Définir la variable de contrôle sur False (arrêter l'exécution)
    return jsonify({'message': 'Traitement en pause.'})

@app.route('/packets', methods=['GET'])
def get_packets():
    packets = Firewall.query.all()
    packet_data = []
    for packet in packets:
        packet_info = {
            'source_port': packet.source_port,
            'destination_port': packet.destination_port,
            'nat_source_port': packet.nat_source_port,
            'nat_destination_port': packet.nat_destination_port,
            'bytes': packet.bytes,
            'bytes_sent': packet.bytes_sent,
            'bytes_received': packet.bytes_received,
            'packets': packet.packets,
            'elapsed_time_sec': packet.elapsed_time_sec,
            'pkts_sent': packet.pkts_sent,
            'pkts_received': packet.pkts_received,
            'action': packet.action,
            'timestamp':packet.timestamp
        }
        packet_data.append(packet_info)
    return jsonify(packet_data)

if __name__ == '__main__':
    app.run(debug=True)
