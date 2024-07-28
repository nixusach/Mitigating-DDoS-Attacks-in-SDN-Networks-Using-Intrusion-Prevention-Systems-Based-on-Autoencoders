from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Packet(Base):
    __tablename__ = 'sdn_packets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    Timestamp = Column(Float)
    Ip_src = Column(String)
    Ip_dst = Column(String)
    Port_src = Column(Integer)
    Port_dst = Column(Integer)
    Ip_protocole = Column(String)
    Type_protocole = Column(String)
    Icmp_type = Column(Integer)
    Flow_duration = Column(Float)
    Packet_count = Column(Integer)
    Byte_count = Column(Integer)
    Traffic = Column(String)
    Attack_type = Column(String)

class History(Base):
    __tablename__ = 'history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    Timestamp = Column(Float)
    Attack_type = Column(String(50))
    Attacker = Column(String(50))
    Victim = Column(String(50))
    Port = Column(String(50))
    Action = Column(String(50))
    Protocole = Column(String(50))

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    Name = Column(String(150), unique=True)
    Email = Column(String(150), unique=True)
    Password = Column(String(150))

class Packets_dropped(Base):
    __tablename__ = 'packets_dropped'
    id = Column(Integer, primary_key=True)
    Count = Column(Integer)

# Create the database engine
db_path = '/mnt/hgfs/instance/sdn.db'
engine = create_engine(f'sqlite:///{db_path}')
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()

def initialize_admin():
    admin = session.query(User).filter_by(Email='admin@gmail.com').first()
    if not admin:
        admin = User(Name='admin', Email='admin@gmail.com', Password='admin')
        session.add(admin)
        session.commit()
        print("Admin user added successfully!")
    else:
        print("Admin user already exists!")

if __name__ == "__main__":
    initialize_admin()

